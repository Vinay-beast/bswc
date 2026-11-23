import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scanner import (RepositoryDiscovery, RepositoryScanner, build_reports, declarations,
                     excluded, find_syft, source_imports, DEFAULT_EXCLUDES)


class SourceTests(unittest.TestCase):
    def test_recursive_discovery_excludes_and_imports_are_not_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nested').mkdir()
            (root / 'nested/main.py').write_text('import requests\nfrom .local import helper\n', encoding='utf-8')
            (root / '.git').mkdir()
            (root / '.git/ignored').write_text('ignore', encoding='utf-8')
            (root / 'nested/package.json').write_text('{"dependencies":{"express":"^4.0"}}', encoding='utf-8')
            result = RepositoryDiscovery(root, DEFAULT_EXCLUDES).run()
            self.assertEqual(result['summary']['files'], 2)
            self.assertEqual(result['summary']['sourceLines'], 2)
            self.assertEqual(result['imports'][0]['reference'], 'requests')
            self.assertEqual(result['imports'][1]['reference'], '.local')
            self.assertTrue(all(len(f['sha256']) == 64 for f in result['files']))
            decls, warnings = declarations(root, result)
            self.assertFalse(warnings)
            self.assertEqual([d['name'] for d in decls], ['express'])

    def test_exclusions_root_nested_and_directory_shorthand(self):
        for path in ['.git', 'sub/.git/config', '.git/config']:
            self.assertTrue(excluded(path, ['**/.git/**']))
        self.assertTrue(excluded('vendor/a/file.py', ['vendor']))
        self.assertFalse(excluded('myvendor/file.py', ['vendor']))

    def test_syntax_failure_is_reported(self):
        warnings = []
        self.assertEqual(source_imports('def broken(', 'Python', 'broken.py', warnings), [])
        self.assertIn('broken.py:1', warnings[0])

    def test_setup_python_is_parsed_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'must-not-exist'
            code = ('from pathlib import Path\n'
                    f'Path({str(marker)!r}).write_text("executed")\n'
                    'requires=["requests>=2.0"]\n'
                    'setup(install_requires=requires, tests_require=dynamic(), extras_require={"extra":["Flask>=3"]})\n')
            (root / 'setup.py').write_text(code, encoding='utf-8')
            inventory = RepositoryDiscovery(root).run()
            result, warnings = declarations(root, inventory)
            self.assertFalse(marker.exists())
            self.assertEqual({d['name'] for d in result}, {'requests', 'Flask'})
            self.assertTrue(any('dynamic tests_require' in w for w in warnings))

    def test_common_manifest_declarations_and_malformed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = {
                'pyproject.toml': '[project]\nname="demo"\ndependencies=["Flask>=3.0"]\n',
                'Cargo.toml': '[dependencies]\nserde="1.0"\n',
                'app.csproj': '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.*" /></ItemGroup></Project>',
                'composer.json': '{"require":{"vendor/lib":"^2.0","php":">=8"}}',
                'package.json': '{broken',
            }
            for name, text in inputs.items():
                (root / name).write_text(text, encoding='utf-8')
            inventory = RepositoryDiscovery(root).run()
            result, warnings = declarations(root, inventory)
            self.assertEqual({d['ecosystem'] for d in result}, {'pypi', 'cargo', 'nuget', 'composer'})
            self.assertEqual(len(warnings), 1)
            self.assertIn('package.json', warnings[0])

    def test_large_text_and_symlink_skip_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'big.py').write_text('import ignored\n' * 10, encoding='utf-8')
            result = RepositoryDiscovery(root, max_text_bytes=10).run()
            self.assertFalse(result['files'][0]['textAnalyzed'])
            self.assertFalse(result['imports'])
            self.assertIn('above 10 bytes', result['warnings'][0])
            try:
                (root / 'link.py').symlink_to(root / 'big.py')
            except OSError:
                return  # Creating symlinks requires extra privileges on some Windows installations.
            result = RepositoryDiscovery(root).run()
            self.assertEqual(result['summary']['files'], 1)
            self.assertEqual(result['skipped']['symlinksOrSpecialFiles'], 1)

    def test_missing_syft_fails_without_fake_fallback(self):
        with self.assertRaisesRegex(RuntimeError, 'No fallback scan'):
            find_syft('/definitely/not/installed/syft')


class GraphTests(unittest.TestCase):
    def test_dependency_direction_and_declaration_versions(self):
        inventory = {'files': [], 'buildReferences': [], 'warnings': [], 'summary': {'files': 0}}
        native = {'artifacts': [
            {'id': 'app', 'name': 'app', 'version': '1.0', 'type': 'npm', 'locations': [{'path': '/app/package-lock.json'}]},
            {'id': 'dep', 'name': 'express', 'version': '4.21.2', 'type': 'npm', 'locations': [{'path': '/app/package-lock.json'}]},
        ], 'artifactRelationships': [{'parent': 'dep', 'child': 'app', 'type': 'dependency-of'}]}
        original = {'bomFormat': 'CycloneDX', 'metadata': {'component': {'bom-ref': 'root'}},
                    'components': [{'bom-ref': 'app', 'name': 'app'}, {'bom-ref': 'dep', 'name': 'express'}],
                    'dependencies': [{'ref': 'app', 'dependsOn': ['dep']}]}
        declared = [{'path': 'app/package.json', 'ecosystem': 'npm', 'name': 'express', 'constraint': '^4.0', 'usage': 'runtime'},
                    {'path': 'unlocked/package.json', 'ecosystem': 'npm', 'name': 'express', 'constraint': '^5.0', 'usage': 'runtime'}]
        graph, bom = build_reports(Path('/sample'), native, original, inventory, declared)
        edge = next(e for e in graph['edges'] if e['kind'] == 'depends-on')
        self.assertEqual((edge['from'], edge['to']), ('app', 'dep'))
        unresolved = next(c for c in bom['components'] if c['bom-ref'].startswith('declared:'))
        self.assertNotIn('version', unresolved)
        self.assertEqual(graph['summary']['declaredOnlyPackages'], 1)
        self.assertIn({'ref': 'app', 'dependsOn': ['dep']}, bom['dependencies'])
        self.assertEqual(len(original['components']), 2)  # Raw Syft evidence is not mutated.
        self.assertTrue(all(p.get('bomRef') for p in graph['nodes'] if p['kind'] == 'package'))

    def test_empty_inventory_reports_unknown_coverage(self):
        native = {'artifacts': [], 'artifactRelationships': []}
        original = {'metadata': {'component': {'bom-ref': 'root'}}, 'components': []}
        inventory = {'files': [], 'buildReferences': [], 'warnings': [], 'summary': {}}
        graph, _ = build_reports(Path('/empty'), native, original, inventory, [])
        self.assertEqual(graph['summary']['packages'], 0)
        self.assertTrue(any('not evidence' in warning for warning in graph['warnings']))


class SyftIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.executable = find_syft()
        except RuntimeError:
            raise unittest.SkipTest('Install Syft to run the actual cataloger integration test')

    def test_actual_polyglot_scan_and_sbom_graph_integrity(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            output = Path(directory) / 'report'
            fixture = Path(__file__).resolve().parent / 'examples/polyglot'
            graph = RepositoryScanner(fixture, output, self.executable).execute()
            self.assertTrue({'npm', 'pypi', 'cargo', 'golang', 'maven', 'nuget', 'composer', 'gem', 'githubactions'} <= set(graph['ecosystems']))
            self.assertGreater(graph['summary']['dependencyEdges'], 0)
            self.assertTrue(any(n['name'] == 'typescript' and n.get('usage') == 'development' for n in graph['nodes']))
            packages = {n['id']: n for n in graph['nodes'] if n['kind'] == 'package'}
            pair_names = {(packages[e['from']]['name'], packages[e['to']]['name']) for e in graph['edges'] if e['kind'] == 'depends-on'}
            self.assertIn(('express', 'accepts'), pair_names)
            bom = json.loads((output / 'cyclonedx-sbom.json').read_text(encoding='utf-8'))
            all_refs = {c['bom-ref'] for c in bom['components']} | {bom['metadata']['component']['bom-ref']}
            self.assertEqual(len(bom['components']), len({c['bom-ref'] for c in bom['components']}))
            for dep in bom['dependencies']:
                self.assertIn(dep['ref'], all_refs)
                self.assertTrue(set(dep['dependsOn']) <= all_refs)
            self.assertTrue(all(p['bomRef'] in all_refs for p in packages.values()))
            flask = next(c for c in bom['components'] if c['name'] == 'flask')
            self.assertNotIn('version', flask)
            raw = json.loads((output / 'syft-sbom.cdx.json').read_text(encoding='utf-8'))
            for component in raw['components']:
                self.assertIn(component, bom['components'])
            native = json.loads((output / 'syft-sbom.json').read_text(encoding='utf-8'))
            self.assertEqual(len(native['artifacts']), graph['summary']['syftPackages'])
            html = (output / 'dashboard.html').read_text(encoding='utf-8')
            self.assertNotIn('/*__GRAPH__*/null', html)
            self.assertNotIn('OWASP Juice Shop', html)

    def test_exclusions_apply_to_syft_and_nested_output(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory) / 'source'
            root.mkdir()
            (root / 'vendor').mkdir()
            (root / 'vendor/requirements.txt').write_text('requests==2.32.3\n', encoding='utf-8')
            (root / 'requirements.txt').write_text('flask==3.0.0\n', encoding='utf-8')
            output = root / 'reports'
            graph = RepositoryScanner(root, output, self.executable, excludes=['vendor']).execute()
            self.assertFalse(any(n['name'] == 'requests' for n in graph['nodes']))
            self.assertTrue(any(n['name'] == 'flask' for n in graph['nodes']))
            source = json.loads((output / 'source-analysis.json').read_text(encoding='utf-8'))
            self.assertEqual(source['summary']['files'], 1)
            graph = RepositoryScanner(root, output, self.executable, excludes=['vendor/**']).execute()
            self.assertFalse(any(n['name'] == 'requests' for n in graph['nodes']))
            source = json.loads((output / 'source-analysis.json').read_text(encoding='utf-8'))
            self.assertEqual(source['summary']['files'], 1)  # Previous reports aren't rescanned.


if __name__ == '__main__':
    unittest.main()
