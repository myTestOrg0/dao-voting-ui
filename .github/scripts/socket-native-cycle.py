"""Opt-in live native resolution lifecycle test, scoped to one repo/package/CVE.

No policy is modified. Every resolution created by this test is deleted in finally;
an additional always-run workflow cleanup step can retry using the ownership record.
"""
import base64
import importlib.util
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('socket_summary', Path(__file__).with_name('socket-summary.py'))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)
TARGET = {'name': 'lodash', 'version': '4.17.11', 'cve': 'CVE-2019-10744', 'type': 'criticalCVE'}


class SocketAPI:
    def __init__(self):
        self.token = os.environ['SOCKET_SECURITY_API_KEY']
        self.org = os.environ['SOCKET_ORG']

    def call(self, method, path, payload=None, raw=False):
        headers = {'Authorization': 'Basic ' + base64.b64encode((self.token + ':').encode()).decode(),
                   'Content-Type': 'application/json'}
        request = Request('https://api.socket.dev/v0/orgs/' + quote(self.org, safe='') + '/' + path,
                          headers=headers, method=method,
                          data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with urlopen(request, timeout=120) as response:
                text = response.read().decode()
                print(f'Native lifecycle HTTP {response.status}: {method} {path}')
                return text if raw else (json.loads(text) if text else {})
        except HTTPError as error:
            raise RuntimeError(f'Native lifecycle HTTP {error.code}: {method} {path}') from None


def selector(repo):
    return {'location.repo': repo, 'artifact.type': 'npm', 'artifact.namespace': '',
            'artifact.name': TARGET['name'], 'artifact.version': TARGET['version'],
            'finding.alertType': TARGET['type'], 'finding.cveId': TARGET['cve']}


def owned_record(folder, row):
    (folder / 'cleanup-state.json').write_text(json.dumps(row, indent=2))


def cleanup(api, folder):
    path = folder / 'cleanup-state.json'
    if not path.exists():
        return False
    state = json.loads(path.read_text())
    if state.get('deleted'):
        return True
    uuid = state['uuid']
    if not re.fullmatch(r'[a-zA-Z0-9-]+', uuid):
        raise ValueError('Invalid owned resolution ID')
    current = api.call('GET', 'alerts/resolutions/' + uuid)
    if current.get('comment') != state['comment'] or current.get('vigil_selector') != state['selector']:
        raise ValueError('Resolution ownership/scope changed; refuse to delete an unrelated record')
    api.call('DELETE', 'alerts/resolutions/' + uuid)
    state['deleted'] = True
    owned_record(folder, state)
    print('Deleted temporary POC resolution: ' + uuid)
    return True


def lifecycle(api, scan, folder, repo, run_marker):
    result = {'kind': 'live_native_resolution_lifecycle', 'target': TARGET, 'repo': repo,
              'policy_modified': False, 'resolution_deleted': False, 'phases': [], 'status': 'incomplete'}
    scope = selector(repo)
    comment = 'Temporary Socket POC lifecycle ' + run_marker
    payload = {'reason': 'other', 'reason_text': 'Temporary integration test, not an applicability assessment',
               'comment': comment, 'vigil_selector': scope}
    creation_attempted = False
    try:
        baseline = scan('baseline')
        result['phases'].append(baseline)
        if len(baseline.get('controls', {})) != 2:
            raise ValueError('Two control findings are required to verify exclusion scope')
        if baseline.get('target_action') != 'warn':
            raise ValueError('Expected an existing Warn target; do not create an exclusion for an unknown baseline')
        rehearsal = api.call('POST', 'alerts/resolutions?dry_run=true', payload)
        if rehearsal.get('dry_run') is not True or rehearsal.get('vigil_selector') != scope:
            raise ValueError('Native API dry-run did not confirm the exact requested selector')
        creation_attempted = True
        created = api.call('POST', 'alerts/resolutions', payload)
        uuid = created.get('uuid')
        if not uuid:
            raise ValueError('Create response missing resolution UUID; inspect API before retrying')
        state = {'uuid': uuid, 'comment': comment, 'selector': scope, 'deleted': False}
        owned_record(folder, state)
        result['resolution_uuid'] = uuid
        result['selector'] = scope
        print('Created temporary POC resolution: ' + uuid)
        stored = api.call('GET', 'alerts/resolutions/' + uuid)
        if stored.get('vigil_selector') != scope or stored.get('comment') != comment:
            raise ValueError('Stored resolution scope differs from the requested scope')
        result['creation_and_read_verified'] = True
        active = scan('resolution_active')
        result['phases'].append(active)
        result['suppression_observed'] = active.get('target_action') in ('ignore', 'absent')
    except Exception as error:
        result['error'] = str(error)
    finally:
        try:
            # A timed-out create can persist a row without returning its UUID.
            # Recover only this run's exact marker AND selector, never another row.
            if creation_attempted and not (folder / 'cleanup-state.json').exists():
                cursor = None
                for _ in range(10):
                    path = 'alerts/resolutions?per_page=100'
                    if cursor:
                        path += '&startAfterCursor=' + quote(cursor, safe='')
                    page = api.call('GET', path)
                    matches = [row for row in page.get('items', [])
                               if row.get('comment') == comment and row.get('vigil_selector') == scope]
                    if matches:
                        if len(matches) != 1:
                            raise ValueError('Multiple records carry the exact test ownership marker')
                        owned_record(folder, {'uuid': matches[0]['uuid'], 'comment': comment,
                                              'selector': scope, 'deleted': False})
                        result['recovered_created_uuid'] = matches[0]['uuid']
                        break
                    cursor = page.get('endCursor')
                    if not cursor:
                        break
            result['resolution_deleted'] = cleanup(api, folder)
        except Exception as error:
            result['cleanup_error'] = str(error)
    if result['resolution_deleted']:
        try:
            restored = scan('after_revoke')
            result['phases'].append(restored)
            result['restoration_observed'] = restored.get('target_action') == 'warn'
            baseline_controls = result['phases'][0].get('controls')
            result['controls_unchanged'] = all(p.get('controls') == baseline_controls for p in result['phases'])
            # New native suppression may apply only to org snapshots rather than full-scan actions.
            result['status'] = 'passed' if (result.get('suppression_observed') and result.get('restoration_observed')
                                           and result.get('controls_unchanged') and not result.get('error')) else 'partial'
        except Exception as error:
            result['verification_error'] = str(error)
    return result


def main():
    folder = Path(os.environ['SOCKET_RESULTS_DIR'])
    folder.mkdir(parents=True, exist_ok=True)
    api = SocketAPI()
    if '--cleanup-only' in sys.argv:
        cleanup(api, folder)
        return 0

    def scan(phase):
        cli = subprocess.run(['socket', 'scan', 'create', '--org', api.org,
                              '--repo', os.environ['SOCKET_REPO'], '--branch', os.environ['GITHUB_REF_NAME'],
                              '--commit-hash', os.environ['GITHUB_SHA'], '--no-set-as-alerts-page', '--json', '.'],
                             capture_output=True, text=True, timeout=240)
        if cli.returncode:
            raise RuntimeError(f'{phase}: Socket scan creation failed, exit {cli.returncode}')
        output = summary.parse_cli_result(cli.stdout)
        if not output.get('ok') or not output.get('data', {}).get('id'):
            raise RuntimeError(f'{phase}: no valid created scan ID')
        scan_id = output['data']['id']
        raw = api.call('GET', f'full-scans/{scan_id}?include_license_details=true', raw=True)
        artifacts = [json.loads(line) for line in raw.splitlines() if line.strip()]
        rows, _, count = summary.collect_findings(artifacts)
        if not count:
            raise ValueError(f'{phase}: no verified component coverage')
        target = [x for x in rows if x['package'] == TARGET['name'] and x['version'] == TARGET['version'] and x['id'] == TARGET['cve']]
        if not any(x['package'] == TARGET['name'] and x['version'] == TARGET['version'] for x in rows):
            raise ValueError(f'{phase}: target component/other findings not present; suppression cannot be inferred')
        controls = {x['id']: x['action'] for x in rows if x['package'] == TARGET['name'] and x['version'] == TARGET['version']
                    and x['id'] in ('CVE-2020-8203', 'CVE-2021-23337')}
        phase_result = {'phase': phase, 'scan_id': scan_id, 'components': count,
                        'target_action': target[0]['action'] if target else 'absent',
                        'target_action_source': target[0].get('action_source') if target else None,
                        'controls': controls, 'actions': dict(Counter(x['action'] for x in rows)),
                        'server_exit_code': summary.server_exit_code(rows)}
        (folder / f'{phase}.json').write_text(json.dumps(phase_result, indent=2))
        print('Native lifecycle scan: ' + json.dumps(phase_result))
        return phase_result

    result = lifecycle(api, scan, folder, os.environ['SOCKET_REPO'],
                       os.environ['GITHUB_RUN_ID'] + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1'))
    # Redact credentials even when an underlying exception includes a request detail.
    text = json.dumps(result, indent=2).replace(api.token, '[redacted]')
    text = text.replace(base64.b64encode((api.token + ':').encode()).decode(), '[redacted]')
    (folder / 'native-cycle.json').write_text(text)
    print('Native lifecycle outcome: ' + result['status'])
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write('## Native resolution lifecycle\n\nStatus: **' + result['status'] + '**\n\n')
        stream.write('| Phase | Target action | Components | Server exit |\n|---|---|---:|---:|\n')
        for phase in result['phases']:
            stream.write(f"| {phase['phase']} | {phase['target_action']} | {phase['components']} | {phase['server_exit_code']} |\n")
        stream.write(f"\nTemporary resolution deleted: **{result['resolution_deleted']}**. No policy was modified.\n")
        if result.get('error'):
            stream.write('\nVerification did not complete; inspect native-cycle.json.\n')
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
