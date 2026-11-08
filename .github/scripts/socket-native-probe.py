"""Probe native resolution read/dry-run support, persisting no exclusions."""
import base64
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


def probe():
    token = os.environ.get('SOCKET_SECURITY_API_KEY', '')
    folder = Path(os.environ['SOCKET_RESULTS_DIR'])
    folder.mkdir(parents=True, exist_ok=True)
    results = {'kind': 'live_api_capability_probe', 'mutations_persisted': False, 'checks': []}
    org = quote(os.environ['SOCKET_ORG'], safe='')
    selector = {'location.repo': os.environ['SOCKET_REPO'], 'artifact.type': 'npm',
                'artifact.name': 'lodash', 'artifact.version': '4.17.11',
                'finding.alertType': 'criticalCVE'}
    requests = [('list', 'GET', '?per_page=1', None),
                ('create_dry_run', 'POST', '?dry_run=true',
                 {'reason': 'other', 'reason_text': 'POC API validation only',
                  'comment': 'Dry run only; no exception is persisted.', 'vigil_selector': selector})]
    for name, method, query, payload in requests:
        row = {'name': name, 'method': method, 'dry_run': name == 'create_dry_run'}
        if not token:
            row.update(status='blocked', reason='Socket secret unavailable')
        else:
            headers = {'Authorization': 'Basic ' + base64.b64encode((token + ':').encode()).decode(),
                       'Content-Type': 'application/json'}
            request = Request(f'https://api.socket.dev/v0/orgs/{org}/alerts/resolutions{query}',
                              data=json.dumps(payload).encode() if payload else None,
                              headers=headers, method=method)
            try:
                with urlopen(request, timeout=30) as response:
                    data = json.load(response)
                    row.update(http_status=response.status, status='supported',
                               response_fields=list(data) if isinstance(data, dict) else ['array'])
                    if name == 'create_dry_run' and (response.status != 200 or not data.get('dry_run')):
                        row.update(status='unverified', reason='Unexpected dry-run response contract')
            except HTTPError as error:
                row.update(http_status=error.code, status='blocked',
                           reason='API rejected the request; check scopes, quota and feature availability')
            except (URLError, TimeoutError, ValueError):
                row.update(status='blocked', reason='API request or JSON response failed')
        results['checks'].append(row)
        print('Native resolution probe: ' + json.dumps(row))
    (folder / 'native-probe.json').write_text(json.dumps(results, indent=2))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('\n### Native exclusion API capability probe\n\nNo resolution was created or deleted. This probe does not prove end-to-end suppression.\n\n')
            for row in results['checks']:
                stream.write(f"- {row['name']}: {row['status']}, HTTP {row.get('http_status', 'n/a')}\n")


if __name__ == '__main__':
    probe()
