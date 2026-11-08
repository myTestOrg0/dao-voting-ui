import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('native_cycle', Path(__file__).parents[1] / 'socket-native-cycle.py')
cycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cycle)


class FakeAPI:
    def __init__(self, lose_create_response=False):
        self.calls = []
        self.record = None
        self.lose_create_response = lose_create_response

    def call(self, method, path, payload=None):
        self.calls.append((method, path))
        if method == 'POST' and 'dry_run' in path:
            return dict(payload, dry_run=True)
        if method == 'POST':
            self.record = dict(payload, uuid='owned-123')
            if self.lose_create_response:
                raise TimeoutError('create response lost')
            return self.record
        if method == 'GET' and '?' in path:
            return {'items': [self.record] if self.record else [], 'endCursor': None}
        if method == 'GET':
            return self.record
        if method == 'DELETE':
            self.record = None
            return {}
        raise AssertionError((method, path))


def phase(action):
    return {'target_action': action, 'controls': {'CVE-2020-8203': 'warn', 'CVE-2021-23337': 'warn'}}


class NativeCycleTests(unittest.TestCase):
    def run_cycle(self, api, scan):
        with tempfile.TemporaryDirectory() as directory:
            return cycle.lifecycle(api, scan, Path(directory), 'test-repo', 'unique-test-marker')

    def test_full_lifecycle_deletes_owned_resolution(self):
        api = FakeAPI()
        actions = iter(['warn', 'ignore', 'warn'])
        result = self.run_cycle(api, lambda name: dict(phase(next(actions)), phase=name))
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['resolution_deleted'])
        self.assertIsNone(api.record)
        self.assertEqual(sum(method == 'DELETE' for method, _ in api.calls), 1)

    def test_scan_failure_still_deletes_resolution(self):
        api = FakeAPI()
        def scan(name):
            if name == 'resolution_active':
                raise RuntimeError('scan unavailable')
            return dict(phase('warn'), phase=name)
        result = self.run_cycle(api, scan)
        self.assertNotEqual(result['status'], 'passed')
        self.assertTrue(result['resolution_deleted'])
        self.assertIsNone(api.record)

    def test_successful_crud_does_not_prove_suppression(self):
        api = FakeAPI()
        result = self.run_cycle(api, lambda name: dict(phase('warn'), phase=name))
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['suppression_observed'])
        self.assertTrue(result['resolution_deleted'])

    def test_ambiguous_create_response_recovers_only_owned_row(self):
        api = FakeAPI(lose_create_response=True)
        result = self.run_cycle(api, lambda name: dict(phase('warn'), phase=name))
        self.assertTrue(result['resolution_deleted'])
        self.assertEqual(result['recovered_created_uuid'], 'owned-123')
        self.assertIsNone(api.record)

    def test_refuse_to_delete_changed_scope_or_foreign_record(self):
        api = FakeAPI()
        api.record = {'uuid': 'owned-123', 'comment': 'someone else', 'vigil_selector': {'location.repo': 'other'}}
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            cycle.owned_record(folder, {'uuid': 'owned-123', 'comment': 'unique-test-marker',
                                       'selector': cycle.selector('test-repo'), 'deleted': False})
            with self.assertRaises(ValueError):
                cycle.cleanup(api, folder)
        self.assertFalse(any(method == 'DELETE' for method, _ in api.calls))


if __name__ == '__main__':
    unittest.main()
