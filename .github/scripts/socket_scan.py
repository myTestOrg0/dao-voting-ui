"""Run manifest/reachability scans and keep findings separate from execution errors."""
import base64
import json
import os
import re
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from socket_report import collect_findings, parse_cli_result, save, verdict
from socket_vex import evaluate
from socket_vex_sources import load_sources


def get_api(org, path):
    token = os.environ.get('SOCKET_SECURITY_API_KEY')
    if not token:
        raise ValueError('Socket API secret is unavailable')
    auth = base64.b64encode((token + ':').encode()).decode()
    request = Request(f"https://api.socket.dev/v0/orgs/{quote(org, safe='')}/{path}",
                      headers={'Authorization': 'Basic ' + auth})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=45) as response:
                return response.read().decode()
        except HTTPError as error:
            error.close()
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise ValueError(f'Socket API returned HTTP {error.code}') from None
        except (URLError, TimeoutError):
            if attempt == 2:
                raise ValueError('Socket API is unavailable or timed out') from None
        time.sleep(2 ** attempt)


def create_scan(folder, report):
    command = ['socket', 'scan', 'create', '--org', report['org'], '--repo', os.environ['SOCKET_REPO'],
               '--branch', report['branch'], '--commit-hash', report['commit'], '--json']
    if os.environ.get('SOCKET_PUBLISH_BASELINE') == 'true':
        if report['branch'] != 'develop':
            raise ValueError('Only develop may publish the dashboard baseline')
        command += ['--default-branch', '--set-as-alerts-page']
    else:
        command += ['--no-set-as-alerts-page']
    if report['reach_requested']:
        command += ['--reach', '--reach-version', '15.14.1', '--reach-disable-analytics',
                    '--reach-analysis-timeout', '5m', '--reach-analysis-memory-limit', '4GB',
                    '--reach-fallback-to-regular-scan']
    process = subprocess.run(command + ['.'], capture_output=True, text=True, timeout=900)
    (folder / 'cli-output.log').write_text(process.stdout)
    (folder / 'cli-error.log').write_text(process.stderr)
    report['creation_exit_code'] = process.returncode
    if process.returncode:
        raise ValueError(f'Socket scan creation failed, process exit {process.returncode}; no policy verdict is available')
    result = parse_cli_result(process.stdout)
    if not result['ok'] or not (result.get('data') or {}).get('id'):
        raise ValueError('Socket did not return a completed scan creation result')
    report['scan_id'] = result['data']['id']
    report['fallback'] = result.get('reachabilityFallback')
    if report['fallback'] is not None and not isinstance(report['fallback'], dict):
        report['fallback'] = None
        raise ValueError('Malformed reachability fallback metadata')
    if not re.fullmatch(r'[A-Za-z0-9-]+', report['scan_id']):
        raise ValueError('Invalid Socket scan ID')


def apply_vex(folder, rows, target):
    config = json.loads((Path(__file__).parents[1] / 'socket-vex-sources.json').read_text())
    # Compare central VEX independently from native Socket resolutions.
    for row in rows:
        if row['vulnerability'] and row['action'] == 'ignore':
            row['server_action_before_vex'] = 'ignore'
            row['action'] = 'monitor'
    sources = load_sources(config, rows, target)
    effective = evaluate(rows, sources, config['product_id'])
    provenance = [{key: value for key, value in source.items() if key != 'document'} for source in sources]
    (folder / 'vex-provenance.json').write_text(json.dumps(provenance, indent=2))
    return effective, provenance


def verify_baseline(folder, report):
    repo = json.loads(get_api(report['org'], 'repos/' + quote(os.environ['SOCKET_REPO'], safe='')))
    head = {key: repo.get(key) for key in ('default_branch', 'head_full_scan_id')}
    head['matches'] = head['default_branch'] == 'develop' and head['head_full_scan_id'] == report['scan_id']
    (folder / 'baseline-head.json').write_text(json.dumps(head, indent=2))
    if not head['matches']:
        raise ValueError('Socket dashboard head does not match the develop scan')


def main():
    folder = Path(os.environ['SOCKET_RESULTS_DIR'])
    folder.mkdir(parents=True, exist_ok=True)
    rows = []
    report = {'org': os.environ['SOCKET_ORG'], 'branch': os.environ['SCAN_BRANCH'],
              'commit': '', 'mode': os.environ.get('SOCKET_MODE', 'policy'),
              'reach_requested': os.environ.get('SOCKET_REACH') == 'true',
              'fallback': None, 'errors': [], 'verification_complete': False, 'exit_code': 2}
    phase = 'configuration'
    try:
        if report['mode'] not in ('policy', 'vex'):
            raise ValueError('Expected policy or vex evaluation mode')
        report['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        phase = 'scan creation'
        create_scan(folder, report)
        phase = 'Socket result collection'
        raw = get_api(report['org'], f"full-scans/{report['scan_id']}?include_license_details=true")
        artifacts = [json.loads(line) for line in raw.splitlines() if line.strip()]
        (folder / 'scan-artifacts.json').write_text(json.dumps(artifacts))
        rows, _, report['components'] = collect_findings(artifacts)
        unknown = any(alert.get('action') not in ('error', 'block', 'warn', 'monitor', 'ignore')
                      for artifact in artifacts if isinstance(artifact, dict)
                      for alert in (artifact.get('alerts') or []))
        if not report['components'] or unknown:
            raise ValueError('Component coverage or server actions cannot be verified')
        if report['mode'] == 'vex':
            phase = 'VEX verification'
            target = 'application' if report['reach_requested'] else 'manifest'
            rows, report['sources'] = apply_vex(folder, rows, target)
        if os.environ.get('SOCKET_PUBLISH_BASELINE') == 'true':
            phase = 'dashboard head verification'
            verify_baseline(folder, report)
        report.update(exit_code=verdict(rows), verification_complete=True,
                      status='fallback' if report['fallback'] else 'completed')
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        token = os.environ.get('SOCKET_SECURITY_API_KEY', '')
        message = str(error)
        if token:
            message = message.replace(token, '[redacted]').replace(base64.b64encode((token + ':').encode()).decode(), '[redacted]')
        report.update(status='verification_incomplete', exit_code=2)
        report['errors'].append(f'{phase}: {message[:1000]}')
    save(folder, report, rows)
    return report['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
