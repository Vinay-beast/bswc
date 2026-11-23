"""Compare package identities from two CycloneDX documents; comparison is never scan evidence."""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote

from merge_evidence import flatten


def inventory(document):
    packages = [c for c in flatten(document.get('components', []))
                if c.get('type') in ('library', 'framework') and c.get('purl', '').startswith('pkg:npm/')]
    identities, versions = set(), defaultdict(set)
    for component in packages:
        raw = component['purl'].split('?', 1)[0].split('#', 1)[0]
        body = raw[len('pkg:npm/'):]
        if '@' in body.rsplit('/', 1)[-1]:
            name, version = body.rsplit('@', 1)
        else:
            name, version = body, None
        name = unquote(name)
        if version:
            identities.add((name, unquote(version)))
            versions[name].add(unquote(version))
        else:
            versions[name]
    return packages, identities, versions


def compare(reference, candidate, output):
    reference, candidate = Path(reference), Path(candidate)
    ref = json.loads(reference.read_text(encoding='utf-8-sig'))
    actual = json.loads(candidate.read_text(encoding='utf-8-sig'))
    rp, ri, rv = inventory(ref)
    cp, ci, cv = inventory(actual)
    result = {'reference': {'path': str(reference.resolve()), 'sha256': hashlib.sha256(reference.read_bytes()).hexdigest(),
                            'packageRecords': len(rp), 'uniqueNames': len(rv), 'uniqueNameVersionPairs': len(ri)},
              'candidate': {'packageRecords': len(cp), 'uniqueNames': len(cv), 'uniqueNameVersionPairs': len(ci)},
              'commonNames': len(set(rv) & set(cv)), 'commonExactNameVersionPairs': len(ri & ci),
              'referenceOnlyNames': sorted(set(rv) - set(cv)), 'candidateOnlyNames': sorted(set(cv) - set(rv)),
              'referenceOnlyExactVersions': [{'name': n, 'version': v, 'candidateVersions': sorted(cv.get(n, []))} for n, v in sorted(ri - ci)],
              'candidateOnlyExactVersions': [{'name': n, 'version': v} for n, v in sorted(ci - ri)],
              'limitations': ['Only npm library/framework records are compared; workflow actions, source files and project roots are excluded.',
                              'Candidate includes backend, frontend, development, optional and peer dependency evidence. Reference scope differs.',
                              'Candidate lockfiles resolve current registry versions. Reference does not establish the same source commit or resolution time.',
                              'Reference input is comparison-only and contributes no package records to the scan.']}
    Path(output).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result
