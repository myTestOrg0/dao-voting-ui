"""Independent VEX advisory verdict after a completed Socket scan."""
import copy
import importlib.util
import json
import os
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


summary = module('summary', 'socket-summary.py')
vex = module('vex', 'socket-vex-evaluate.py')
fetch = module('fetch', 'socket-vex-fetch.py')


def independent_baseline(rows):
    """VEX is the sole vulnerability-exclusion source in this comparison variant."""
    rows = copy.deepcopy(rows)
    for finding in rows:
        if finding.get('vulnerability') and finding['action'] == 'ignore':
            finding['server_action_before_vex'] = 'ignore'
            finding['action'] = 'monitor'
    return rows


def main():
    folder = Path(os.environ['SOCKET_RESULTS_DIR'])
    folder.mkdir(parents=True, exist_ok=True)
    os.environ['SOCKET_FAIL_ON_FINDINGS'] = 'true'
    try:
        original = json.loads((folder / 'report.json').read_text())
        if not original.get('verification_complete') or not original.get('components'):
            raise ValueError('Socket collection is incomplete; VEX cannot establish a pass')
        rows = independent_baseline(json.loads((folder / 'findings.json').read_text()))
        config = json.loads(Path('.github/socket-vex-sources.json').read_text())
        sources = fetch.load_sources(config, rows)
        result = vex.evaluate(rows, sources, config['product_id'])
        code = summary.advisory_exit_code(result['findings'])
        unresolved = sum(f.get('vulnerability') and f['action'] != 'ignore' for f in result['findings'])
        provenance = [{k: s[k] for k in ('name', 'repository', 'revision', 'sha256', 'documents', 'npm_coverage')} for s in sources]
        report = {'source': 'Socket inventory + central VEX', 'exit_code': code, 'verification_complete': True,
                  'unresolved_vulnerabilities': unresolved, 'native_resolutions_honored': False,
                  'product_id': config['product_id'], 'scanId': original['scanId'], 'sources': provenance}
        raw = json.loads((folder / 'scan-artifacts.json').read_text())
        manifests = sorted({m['file'] for a in raw for m in a.get('manifestFiles', []) if m.get('file')})
        content = summary.render_summary({'data': {'id': original['scanId']}}, result['findings'], manifests,
                                        original['components'], os.environ['SOCKET_ORG'], os.environ['SCAN_SHA'])
        content = content.replace('## Socket dependency scan', '## Socket VEX advisory check').replace(
            'VEX filtering is not enabled. No PR-comment suppression commands are processed.',
            'VEX priority: own → Docker DHI → Aqua. Native resolutions are not used as vulnerability exclusions in this comparison variant.')
        content += '\n### Central VEX decisions\n\n| Finding | Status | Source |\n|---|---|---|\n'
        for finding in result['findings']:
            if finding.get('vex'):
                choice = finding['vex']
                content += f"| {summary.md(finding['package'])}@{summary.md(finding['version'])} / {summary.md(finding['id'])} | {summary.md(choice['status'])} | {summary.md(choice['source'])} |\n"
        content += '\n### Source snapshots\n\n'
        for source in provenance:
            content += f"- {source['name']}: `{source['revision']}`; npm coverage: {source['npm_coverage']}; documents: {len(source['documents'])}.\n"
        content += '\nNo Docker/Aqua npm document means no vendor exception for this npm scan; it does not mean these feeds were omitted.\n'
        (folder / 'raw-server-report.json').write_text(json.dumps(original, indent=2))
        (folder / 'report.json').write_text(json.dumps(report, indent=2))
        (folder / 'findings-effective.json').write_text(json.dumps(result['findings'], indent=2))
        (folder / 'vex-provenance.json').write_text(json.dumps(provenance, indent=2))
        summary.write_summary(folder, content)
        summary.print_findings(result['findings'], original['components'])
        print(f'VEX advisory exit={code}; unresolved vulnerabilities={unresolved}; check is optional in GitHub branch rules.')
        return code
    except (ValueError, OSError, KeyError, TypeError) as error:
        (folder / 'vex-error.json').write_text(json.dumps({'status': 'verification_incomplete', 'reason': str(error)}))
        summary.write_summary(folder, '## Socket VEX advisory check\n\n**Verification incomplete**\n\n' + summary.md(error))
        print('::error::VEX evaluation incomplete; see Summary and vex-error.json')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
