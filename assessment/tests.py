"""Public CLI contract and source-to-vault coverage checks."""
import csv
import json
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

class AssessmentTests(unittest.TestCase):
    def cli(self, inventory, *args):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'inventory.json'
            path.write_text(json.dumps(inventory), encoding='utf-8')
            return subprocess.run([sys.executable, str(HERE / 'check.py'), '--inventory', str(path), *args], capture_output=True, text=True)

    def test_candidates_are_not_proof_and_mismatches_are_not_absence(self):
        result = self.cli([
            {'asset': 'match', 'vendor': 'isc', 'product': 'bind', 'version': 'unknown'},
            {'asset': 'wrong-vendor', 'vendor': 'Apache', 'product': 'BIND'},
            {'asset': 'substring', 'vendor': 'ISC', 'product': 'BIND-like'},
        ], '--cve', 'CVE-2015-5477')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual([r['status'] for r in rows], ['Candidate', 'Not matched', 'Not matched'])
        self.assertIn('does NOT establish absence', rows[1]['reason'])

    def test_full_catalog_can_be_correlated(self):
        catalog = json.loads((HERE / 'data/catalog.json').read_text(encoding='utf-8'))
        identities = {(r['vendorProject'], r['product']) for r in catalog}
        result = self.cli([{'vendor': v, 'product': p} for v, p in identities])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({r['cve'] for r in json.loads(result.stdout)}, {r['cveID'] for r in catalog})
        self.assertTrue(all(r['status'] == 'Candidate' for r in json.loads(result.stdout)))

    def test_invalid_input_and_unknown_cve(self):
        for inventory, args in [({'asset':'wrong shape'}, []), ([{'vendor':None}], []), ([], ['--cve','CVE-0000-0000'])]:
            result = self.cli(inventory, *args)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('Traceback', result.stderr)

    def test_exact_csv_and_pdf_page_coverage(self):
        with (ROOT / 'known_exploited_vulnerabilities.csv').open(encoding='utf-8-sig', newline='') as f:
            ids = {r['cveID'] for r in csv.DictReader(f)}
        catalog = json.loads((HERE / 'data/catalog.json').read_text(encoding='utf-8'))
        self.assertEqual({r['cveID'] for r in catalog}, ids)
        self.assertEqual({p.stem for p in (ROOT / 'Assessment Vault/CVEs').glob('*.md')}, ids)
        sources = json.loads((HERE / 'data/sources.json').read_text(encoding='utf-8'))
        pages = json.loads((HERE / 'data/pages.json').read_text(encoding='utf-8'))
        source_paths = {str((ROOT / s['path']).resolve()) for s in sources}
        self.assertEqual(source_paths, {str(p.resolve()) for p in [*ROOT.glob('*.pdf'), *(ROOT / 'hacking-main').glob('*.pdf')]})
        for s in sources:
            self.assertEqual([p['page'] for p in pages if p['source'] == s['id']], list(range(1,s['pages']+1)))

    def test_enrichment_preserves_conditions_and_patch_scope(self):
        catalog = json.loads((HERE / 'data/catalog.json').read_text(encoding='utf-8'))
        snapshot = json.loads((HERE / 'research/nvd-kev.json').read_text(encoding='utf-8'))
        original = {item['cve']['id']: item['cve'] for item in snapshot['vulnerabilities']}
        guides = json.loads((HERE / 'data/commands.json').read_text(encoding='utf-8'))['_guides']
        guide_ids = {g['id'] for g in guides}
        for r in catalog:
            self.assertEqual(r['configurations'], original[r['cveID']]['configurations'])
            self.assertTrue(r['nvdDescription'])
            self.assertTrue(r['versionConditions'])
            self.assertTrue(set(r['guideIds']) <= guide_ids)
            note = (ROOT / 'Assessment Vault/CVEs' / (r['cveID'] + '.md')).read_text(encoding='utf-8')
            self.assertIn('### Decision branches', note)
            self.assertIn('### Retest', note)
        by_id = json.loads((HERE / 'cve_overrides.json').read_text(encoding='utf-8'))
        patch = 'https://github.com/strapi/security-patches/tree/main/CVE-2023-22621'
        self.assertIn(patch, [c['url'] for c in by_id['CVE-2023-22621']['code']])
        for cve in ('CVE-2023-22894', 'CVE-2023-22893'):
            self.assertNotIn(patch, [c['url'] for c in by_id[cve]['code']])
        for r in catalog:
            for code in r['codeLinks']:
                if code['kind'] == 'NVD-indexed upstream patch candidate':
                    refs = original[r['cveID']]['references']
                    ref = next(ref for ref in refs if ref['url'] == code['url'])
                    self.assertIn('Patch', ref['tags'])
                    self.assertFalse({'Exploit', 'Broken Link'} & set(ref['tags']))

    def test_training_coverage_and_runnable_fixture_outcomes(self):
        training = json.loads((HERE / 'data/commands.json').read_text(encoding='utf-8'))['_training']
        expected_counts = [8,7,9,12,18,11,34,15,26,9,12,15,9,13]
        self.assertEqual([len(g['topics']) for g in training['groups']], expected_counts)
        self.assertEqual(len(training['labs']), 6)
        expected_notes = set()
        for g in training['groups']:
            self.assertTrue(any(g['id'] in lab['groups'] for lab in training['labs']))
            for i, topic in enumerate(g['topics'], 1):
                name = f"training-{g['id']}-{i:02d}"
                expected_notes.add(name)
                note = (ROOT / 'Assessment Vault/Training/Topics' / (name+'.md')).read_text(encoding='utf-8')
                self.assertTrue(all(value in note for value in topic))
                self.assertIn('### Decision branches', note)
        self.assertEqual({p.stem for p in (ROOT / 'Assessment Vault/Training/Topics').glob('*.md')}, expected_notes)
        lab = next(l for l in training['labs'] if l['id'] == 'pipeline-fixtures')
        result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                                 lab['commands'][0]['code']+' | ConvertTo-Json'],
                                cwd=HERE, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r['Verdict'] for r in json.loads(result.stdout)],
                         ['EXPECTED OBSERVATION','SOURCE GAP','INGESTION GAP','ALERT GAP',
                          'CONTAINMENT GAP','EXPECTED OBSERVATION','UNEXPECTED ALERT','ALERT GAP'])
        aggregate = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                                    lab['commands'][1]['code']+' | ConvertTo-Json'],
                                   cwd=HERE, capture_output=True, text=True)
        self.assertEqual(aggregate.returncode, 0, aggregate.stderr)
        self.assertEqual(json.loads(aggregate.stdout), {'TotalBytes':2400,'LargestEventBytes':600,
                         'Threshold':2000,'AggregateExceeds':True,'SingleEventExceeds':False})

    def test_vault_links_are_unambiguous(self):
        paths = list((ROOT / 'Assessment Vault').rglob('*.md'))
        names = Counter(p.stem.casefold() for p in paths)
        self.assertFalse([name for name, count in names.items() if count > 1])
        broken = []
        for p in paths:
            prose = re.sub(r'```[^\n]*\n.*?```', '', p.read_text(encoding='utf-8'), flags=re.S)
            for link in re.findall(r'\[\[([^\]]+)\]\]', prose):
                target = link.split('|')[0].split('#')[0].casefold()
                if target != 'cve-yyyy-nnnn' and target not in names:
                    broken.append((p.name, link))
        self.assertEqual(broken, [])

if __name__ == '__main__':
    unittest.main(verbosity=2)
