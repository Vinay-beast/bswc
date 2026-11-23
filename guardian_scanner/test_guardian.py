import json
import tempfile
import unittest
from pathlib import Path
from guardian import DiscoveryAgent, NpmResolverAgent, SBOMAgent, GraphAgent, npm_purl

class GuardianTests(unittest.TestCase):
    def test_scoped_purl(self):
        self.assertEqual(npm_purl('@angular/core', '22.0.1'), 'pkg:npm/%40angular/core@22.0.1')

    def test_snapshot_counts_and_unresolved_versions(self):
        root = Path(__file__).resolve().parent
        ws=DiscoveryAgent(root/'snapshots').run()
        agent=NpmResolverAgent(ws)
        nodes,edges=agent.run()
        graph=GraphAgent.run(nodes,edges,agent.warnings,root/'snapshots')
        self.assertEqual(graph['summary']['packages'], 161)
        self.assertEqual(graph['summary']['runtimePackages'],101)
        self.assertEqual(graph['summary']['developmentPackages'],60)
        self.assertEqual(graph['summary']['transitiveEdges'],0)
        self.assertEqual(graph['summary']['unresolvedPackages'],161)
        sbom=SBOMAgent.run(nodes,edges)
        self.assertEqual(sbom['bomFormat'],'CycloneDX')
        self.assertEqual(sbom['specVersion'],'1.6')
        self.assertTrue(any(c['name']=='jsonwebtoken' and 'version' not in c
                            and any(p['name']=='guardian:versionConstraint' and p['value']=='0.4.0'
                                    for p in c['properties']) for c in sbom['components']))

    def test_lock_parser_nested_packages(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'frontend').mkdir()
            pkg={'name':'juice-shop','version':'1.0.0','dependencies':{'a':'^1.0.0'},'devDependencies':{}}
            front={'name':'frontend','version':'1.0.0','dependencies':{'c':'^3.0.0'},'devDependencies':{}}
            (root/'package.json').write_text(json.dumps(pkg))
            (root/'frontend'/'package.json').write_text(json.dumps(front))
            lock={'lockfileVersion':3,'packages':{
                '':{'name':'juice-shop','version':'1.0.0','dependencies':{'a':'^1.0.0'}},
                'node_modules/a':{'version':'1.0.1','dependencies':{'b':'^2.0.0'}},
                'node_modules/b':{'version':'2.1.0','dependencies':{'a':'^1.0.0'}},
                'node_modules/a/node_modules/b':{'version':'2.2.0', 'dependencies':{'@scoped/d':'^4.0.0'}},
                'node_modules/@scoped/d':{'version':'4.0.0'} }}
            (root/'package-lock.json').write_text(json.dumps(lock))
            (root/'frontend'/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':{'name':'frontend'}, 'node_modules/c':{'version':'3.0.2'}}}))
            agent=NpmResolverAgent(DiscoveryAgent(root).run());nodes,edges=agent.run()
            indexed={(e['from'],e['to']): e for e in edges}
            self.assertIn(('app:backend','lock:backend:node_modules/a'),indexed)
            self.assertIn(('lock:backend:node_modules/a','lock:backend:node_modules/a/node_modules/b'),indexed)
            self.assertIn(('lock:backend:node_modules/a/node_modules/b','lock:backend:node_modules/@scoped/d'),indexed)
            b=[n for n in nodes if n['id']=='lock:backend:node_modules/a/node_modules/b'][0]
            self.assertEqual(b['version'],'2.2.0')
            graph=GraphAgent.run(nodes,edges,agent.warnings,root)
            self.assertEqual(graph['summary']['unresolvedPackages'],0)
            sbom=SBOMAgent.run(nodes,edges)
            comp=next(c for c in sbom['components'] if c['bom-ref']==b['id'])
            self.assertEqual(comp['purl'],'pkg:npm/b@2.2.0')

if __name__=='__main__':unittest.main()
