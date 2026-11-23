import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from merge_evidence import package_key, merge
from workflow_evidence import collect


class IdentityTests(unittest.TestCase):
    def test_existing_source_recreates_configuration_for_a_new_checkout(self):
        import fetch_juice_shop
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / 'checkout'
            checkout.mkdir()
            source = Path(directory) / 'source'
            source.mkdir()
            commit = 'a' * 40
            (source / 'GUARDIAN_SOURCE.json').write_text(json.dumps({'commit': commit}), encoding='utf-8')
            with patch.object(fetch_juice_shop, 'ROOT', checkout):
                self.assertEqual(fetch_juice_shop.fetch(commit, source), source)
            configured = json.loads((checkout / '.guardian-target.json').read_text(encoding='utf-8'))
            self.assertEqual(configured['repositoryPath'], str(source))
            self.assertEqual(configured['commit'], commit)

    def test_scoped_npm_identity_deduplicates_encoding_and_qualifiers(self):
        self.assertEqual(package_key({'purl': 'pkg:npm/%40scope/lib@1.0?package-id=123'}),
                         package_key({'purl': 'pkg:npm/@scope/lib@1.0'}))

    def test_workflow_subpaths_are_distinct_and_normalized(self):
        first = package_key({'purl': 'pkg:github/github/codeql-action/init@v3'})
        same = package_key({'purl': 'pkg:github/GitHub/codeql-action@v3#init'})
        other = package_key({'purl': 'pkg:github/github/codeql-action@v3#analyze'})
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)

    def test_sha_pin_is_not_the_version_from_a_yaml_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'frontend').mkdir()
            for name, folder in [('juice-shop', root), ('frontend', root / 'frontend')]:
                (folder / 'package.json').write_text(json.dumps({'name': name, 'version': '1.0'}))
                (folder / 'package-lock.json').write_text('{"packages":{}}')
            (root / 'GUARDIAN_SOURCE.json').write_text(json.dumps({'repository': 'https://github.com/juice-shop/juice-shop', 'commit': 'a' * 40}))
            pin = 'b' * 40
            action = {'id': 'raw-action', 'bomRef': 'raw-action', 'name': 'actions/checkout', 'kind': 'package',
                      'ecosystem': 'githubactions', 'version': 'v4', 'versionStatus': 'reference', 'usage': 'unknown',
                      'purl': 'pkg:github/actions/checkout@v4', 'locations': ['.github/workflows/build.yml'],
                      'cataloger': 'Syft', 'licenses': [], 'declarations': []}
            graph = {'nodes': [{'id': 'root', 'kind': 'repository', 'name': 'juice-shop'}, action],
                     'edges': [], 'summary': {}, 'warnings': [], 'limitations': [], 'engine': {}}
            bom = {'specVersion': '1.6', 'serialNumber': 'urn:uuid:test', 'metadata': {'tools': {'components': []}},
                   'components': [{'bom-ref': 'raw-action', 'type': 'library', 'name': 'actions/checkout', 'version': 'v4', 'purl': action['purl']}]}
            native = {'artifacts': [{'id': 'raw-action', 'type': 'github-action', 'metadata': {'value': 'actions/checkout@' + pin, 'comment': 'v4'}}]}
            extra = root / 'actions.cdx.json'
            extra.write_text(json.dumps({'components': [{'bom-ref': 'second-action', 'type': 'application', 'name': 'checkout',
                              'group': 'actions', 'purl': 'pkg:github/actions/checkout@' + pin, 'version': pin}]}))
            result, final = merge(graph, bom, root, [{'tool': 'cdxgen', 'path': extra, 'workspace': 'workflows'}], native)
            self.assertEqual(result['summary']['workflowActions'], 1)
            package = next(n for n in result['nodes'] if n['kind'] == 'package')
            self.assertEqual(package['version'], pin)
            self.assertEqual(set(package['tools']), {'Syft', 'cdxgen'})
            ids = {n['id'] for n in result['nodes']}
            self.assertTrue(all(e['from'] in ids and e['to'] in ids for e in result['edges']))


class WorkflowTests(unittest.TestCase):
    def test_local_composite_actions_are_followed_without_execution(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory) / 'repo'
            output = Path(directory) / 'report'
            workflows = root / '.github/workflows'
            workflows.mkdir(parents=True)
            workflows.joinpath('build.yml').write_text('name: Build\njobs:\n  test:\n    steps:\n      - uses: ./.github/actions/first\n')
            for name, text in [('first', 'runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/second\n'),
                               ('second', 'runs:\n  using: composite\n  steps:\n    - run: echo must-not-execute\n')]:
                folder = root / '.github/actions' / name
                folder.mkdir(parents=True)
                (folder / 'action.yml').write_text(text)
            result = collect(root, output)
            self.assertEqual(result['workflows'], 1)
            self.assertEqual(result['actionReferences'], 2)
            self.assertEqual(result['metadataDocumentsRead'], 2)
            self.assertFalse(result['warnings'])
            bom = json.loads((output / 'workflow-recursive.cdx.json').read_text())
            refs = {c['bom-ref'] for c in bom['components']} | {bom['metadata']['component']['bom-ref']}
            for dependency in bom['dependencies']:
                self.assertIn(dependency['ref'], refs)
                self.assertTrue(set(dependency['dependsOn']) <= refs)


if __name__ == '__main__':
    unittest.main()
