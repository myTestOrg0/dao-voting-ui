"""Isolated backend precedence experiment; never updates the dashboard head."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.request import urlopen
from socket_report import parse_cli_result
from socket_scan import get_api

out = Path(os.environ['RUNNER_TEMP']) / 'lockfile-probe'
out.mkdir()
with urlopen('https://registry.npmjs.org/lodash/4.17.11') as response:
    old_dist = json.load(response)['dist']
with urlopen('https://registry.npmjs.org/lodash/4.17.21') as response:
    new_dist = json.load(response)['dist']
cases = [
    ('old-consistent', '4.17.11', '4.17.11', '4.17.11'),
    ('compatible-range', '^4.17.0', '^4.17.0', '4.17.11'),
    ('new-manifest-stale-lock', '4.17.21', '4.17.11', '4.17.11'),
    ('new-consistent', '4.17.21', '4.17.21', '4.17.21'),
    ('new-without-lock', '4.17.21', None, None),
]
results = []
for name, spec, selector, version in cases:
    folder = out / name
    folder.mkdir()
    (folder / 'package.json').write_text(json.dumps({'name':'socket-lockfile-probe','version':'1.0.0','private':True,'dependencies':{'lodash':spec}}))
    if selector:
        dist = old_dist if version == '4.17.11' else new_dist
        (folder / 'yarn.lock').write_text(f'# yarn lockfile v1\n\nlodash@{selector}:\n  version "{version}"\n  resolved "{dist["tarball"]}#{dist["shasum"]}"\n  integrity {dist["integrity"]}\n')
    command = ['socket','scan','create','--org','lido-labs','--repo','dao-voting-ui','--branch','lockfile-probe/'+name,'--commit-hash',os.environ['GITHUB_SHA'],'--no-set-as-alerts-page','--json','.']
    process = subprocess.run(command,cwd=folder,capture_output=True,text=True,timeout=180)
    (folder/'cli-output.log').write_text(process.stdout)
    (folder/'cli-error.log').write_text(process.stderr)
    if process.returncode: raise SystemExit(f'Scan failed in {name}, code {process.returncode}')
    created = parse_cli_result(process.stdout)
    if not created['ok']:raise SystemExit(f'Scan not created for {name}')
    scan_id = created['data']['id']
    raw = get_api('lido-labs','full-scans/'+scan_id)
    (folder/'artifacts.ndjson').write_text(raw)
    packages = [json.loads(line) for line in raw.splitlines() if line.strip()]
    actual = [{'version':p['version'],'cves':sorted({a.get('props',{}).get('cveId') or a.get('props',{}).get('ghsaId') or a.get('type') for a in p.get('alerts',[]) if a.get('category')=='vulnerability'})} for p in packages if p.get('name')=='lodash']
    result = {'case':name,'manifest_spec':spec,'lock_selector':selector,'lock_version':version,'scan_id':scan_id,'actual':actual}
    results.append(result)
    print(json.dumps(result))
(out/'results.json').write_text(json.dumps(results,indent=2))
with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as summary:
    summary.write('## Socket lockfile precedence experiment\n\n| Case | Manifest | Lock version | Scanned versions |\n|---|---|---|---|\n')
    for row in results:
        summary.write(f"| {row['case']} | {row['manifest_spec']} | {row['lock_version']} | {', '.join(p['version'] for p in row['actual'])} |\n")
