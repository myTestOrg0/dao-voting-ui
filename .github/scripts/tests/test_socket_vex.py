import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('socket_vex', SCRIPTS / 'socket-vex-evaluate.py')
vex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex)

FINDING = {'ecosystem': 'npm', 'package': 'lodash', 'version': '4.17.11',
           'id': 'CVE-2019-10744', 'ghsa': 'GHSA-jf85-cpcp-j695', 'action': 'error', 'vulnerability': True}
PRODUCT = 'urn:socket-poc:test-product'
NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


def document(status='not_affected', purl='pkg:npm/lodash@4.17.11'):
    return {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'urn:socket-poc:synthetic-test-only',
            'author': 'POC fixture not a production security assessment', 'timestamp': '2026-11-01T00:00:00Z', 'version': 1,
            'statements': [{'vulnerability': {'name': FINDING['id']},
                            'products': [{'@id': PRODUCT, 'subcomponents': [{'@id': purl}]}],
                            'status': status, 'justification': 'vulnerable_code_not_in_execute_path',
                            'action_statement': 'Synthetic test only; remediate before production use.'}]}


class VexTests(unittest.TestCase):
    def source(self, name, doc):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vex.json'
            path.write_text(json.dumps(doc))
            return vex.load_source(name, path, NOW)

    def run_case(self, sources, finding=None, product=PRODUCT):
        return vex.evaluate([finding or FINDING], sources, product)

    def test_applicable_vex_changes_exit_code_and_keeps_raw_action(self):
        self.assertEqual(self.run_case([])['exit_code'], 1)
        result = self.run_case([self.source('own', document())])
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['findings'][0]['original_action'], 'error')
        self.assertEqual(FINDING['action'], 'error')
        self.assertEqual(result['findings'][0]['vex']['source'], 'own')

    def test_priority_both_directions_and_pending(self):
        for status, expected in [('affected', 1), ('under_investigation', 1), ('not_affected', 0)]:
            with self.subTest(status=status):
                result = self.run_case([self.source('own', document(status)), self.source('docker', document())])
                self.assertEqual(result['exit_code'], expected)
                self.assertEqual(result['findings'][0]['vex']['source'], 'own')
        result = self.run_case([self.source('own', document()), self.source('docker', document('affected'))])
        self.assertEqual(result['exit_code'], 0)

    def test_fallback_on_missing_advisory_not_just_missing_package(self):
        own = document('affected')
        own['statements'][0]['vulnerability']['name'] = 'CVE-2099-99999'
        result = self.run_case([self.source('own', own), self.source('docker', document())])
        self.assertEqual(result['findings'][0]['vex']['source'], 'docker')
        docker = copy.deepcopy(own)
        result = self.run_case([self.source('own', own), self.source('docker', docker), self.source('aqua', document())])
        self.assertEqual(result['findings'][0]['vex']['source'], 'aqua')

    def test_scope_version_ecosystem_product_and_qualifiers(self):
        for purl, product in [('pkg:npm/lodash@4.17.12', PRODUCT),
                              ('pkg:deb/debian/lodash@4.17.11', PRODUCT),
                              ('pkg:npm/lodash@4.17.11?arch=arm64', PRODUCT),
                              ('pkg:npm/lodash@4.17.11', 'urn:another-product')]:
            with self.subTest(purl=purl, product=product):
                self.assertEqual(self.run_case([self.source('own', document(purl=purl))], product=product)['exit_code'], 1)

    def test_aliases_and_scoped_packages(self):
        doc = document(purl='pkg:npm/%40scope/name@1.2.3')
        doc['statements'][0]['vulnerability']['name'] = FINDING['ghsa']
        finding = dict(FINDING, package='@scope/name', version='1.2.3')
        self.assertEqual(self.run_case([self.source('own', doc)], finding)['exit_code'], 0)

    def test_expiration_revocation_and_invalid_justification(self):
        doc = document()
        doc['x-poc-expires'] = '2026-11-07T00:00:00Z'
        self.assertEqual(self.run_case([self.source('own', doc)])['exit_code'], 1)
        self.assertEqual(self.run_case([])['exit_code'], 1)  # revoked document
        doc = document()
        del doc['statements'][0]['justification']
        with self.assertRaises(ValueError):
            self.run_case([self.source('own', doc)])

    def test_conflicting_and_unknown_status_fail_verification(self):
        doc = document()
        doc['statements'] += document('affected')['statements']
        with self.assertRaises(ValueError):
            self.run_case([self.source('own', doc)])
        with self.assertRaises(ValueError):
            self.run_case([self.source('own', document('invalid'))])

    def test_unknown_scanner_action_cannot_be_suppressed(self):
        with self.assertRaises(ValueError):
            self.run_case([self.source('own', document())], dict(FINDING, action='unknown'))

    def test_non_vulnerability_not_suppressed(self):
        self.assertEqual(self.run_case([self.source('own', document())], dict(FINDING, vulnerability=False))['exit_code'], 1)

    def test_cli_missing_source_is_error_not_clean_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'findings.json').write_text(json.dumps([FINDING]))
            result = subprocess.run([sys.executable, str(SCRIPTS / 'socket-vex-evaluate.py'),
                                     '--findings', str(path / 'findings.json'), '--product-id', PRODUCT,
                                     '--source', f'own={path}/missing.json', '--output', str(path / 'result.json')], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(json.loads((path / 'result.json').read_text())['verification_complete'])

    def test_hash_pin_accepts_reviewed_lock_and_rejects_mutation(self):
        verify = SCRIPTS / 'verify-socket-lock.py'
        lock = SCRIPTS.parent / 'tools/socket-cli/dependencies.lock'
        good = subprocess.run([sys.executable, str(verify), str(lock)], capture_output=True)
        self.assertEqual(good.returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / 'changed.lock'
            changed.write_bytes(lock.read_bytes() + b' ')
            bad = subprocess.run([sys.executable, str(verify), str(changed)], capture_output=True)
            self.assertEqual(bad.returncode, 1)
            self.assertIn(b'SHA-256 mismatch', bad.stdout)


if __name__ == '__main__':
    unittest.main()
