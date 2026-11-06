import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('socket_summary', Path(__file__).parents[1] / 'socket-summary.py')
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def artifact(namespace='', action='warn'):
    return {'type': 'npm', 'namespace': namespace, 'name': 'sample', 'version': '1.0.0',
            'manifestFiles': [{'file': 'nested/package.json'}], 'alerts': [{
                'type': 'criticalCVE', 'category': 'vulnerability', 'action': action,
                'props': {'cveId': 'CVE-2026-1234', 'ghsaId': 'GHSA-abcd-1234-5678',
                          'severity': 'CRITICAL', 'firstPatchedVersionIdentifier': '1.0.1'}}]}


class SummaryTests(unittest.TestCase):
    def test_progress_and_blocked_result(self):
        result = {'ok': True, 'data': {'healthy': False, 'scanId': 'abc-123'}}
        self.assertEqual(summary.parse_cli_result('progress {invalid}\n' + json.dumps(result)), result)
        with self.assertRaises(ValueError):
            summary.parse_cli_result('Authentication failed')

    def test_dedup_keeps_stricter_action_and_namespaces(self):
        rows, manifests, count = summary.collect_findings([
            artifact(action='ignore'), artifact(action='warn'), artifact('@scope', 'error')])
        self.assertEqual(count, 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['package'], '@scope/sample')
        self.assertEqual(rows[1]['action'], 'warn')
        self.assertEqual(manifests, ['nested/package.json'])

    def test_summary_keeps_resolved_action_and_escapes_markdown(self):
        rows, manifests, count = summary.collect_findings([artifact(action='ignore')])
        result = {'data': {'healthy': True, 'scanId': 'abc-123'}}
        rendered = summary.render_summary(result, rows, manifests, count, 'org', 'a' * 40)
        self.assertIn('Critical 1', rendered)
        self.assertIn('No Block/Warn', rendered)
        self.assertNotIn('| sample |', rendered)
        self.assertEqual(summary.md('<script>|x\ny'), '&lt;script&gt;\\|x y')

    def test_current_scan_fetch_and_failure_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            env = {'SOCKET_RESULTS_DIR': directory, 'SOCKET_ORG': 'org', 'SCAN_SHA': 'a' * 40,
                   'GITHUB_STEP_SUMMARY': str(folder / 'job-summary.md')}
            with patch.dict(os.environ, env):
                self.assertEqual(summary.main(), 1)
                self.assertIn('verification incomplete', (folder / 'summary.md').read_text())
                (folder / 'cli-output.log').write_text(json.dumps({
                    'ok': True, 'data': {'healthy': False, 'scanId': 'current-scan'}}))
                with patch.object(summary, 'get_api', side_effect=[json.dumps(artifact()), '{}']) as fetch:
                    self.assertEqual(summary.main(), 0)
                    self.assertEqual(fetch.call_args_list[0].args, ('org', 'full-scans/current-scan?include_license_details=true'))
                self.assertIn('Policy failed', (folder / 'summary.md').read_text())
                self.assertEqual(len(json.loads((folder / 'findings.json').read_text())), 1)


if __name__ == '__main__':
    unittest.main()
