"""Replay VEX scenarios on one real finding with a synthetic blocking baseline.

Synthetic assessments are fixtures only and must never become production exceptions.
"""
import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def document(status='not_affected', version='4.17.11'):
    return {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'urn:socket-poc:synthetic-only',
            'author': 'POC synthetic fixture not an applicability assessment',
            'timestamp': '2026-11-01T00:00:00Z', 'version': 1,
            'statements': [{'vulnerability': {'name': 'CVE-2019-10744'},
                            'products': [{'@id': 'urn:socket-poc:dao-voting-ui', 'subcomponents': [
                                {'@id': f'pkg:npm/lodash@{version}'}]}],
                            'status': status, 'justification': 'vulnerable_code_not_in_execute_path',
                            'action_statement': 'Synthetic fixture only; no real applicability assessment.'}]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--findings', required=True)
    parser.add_argument('--own-feed-sample')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    rows = json.loads(Path(args.findings).read_text())
    actual = next(x for x in rows if x['package'] == 'lodash' and x['version'] == '4.17.11' and x['id'] == 'CVE-2019-10744')
    baseline = dict(actual, action='error')
    pending = document('under_investigation')
    wrong = document(version='4.17.12')
    expired = document(); expired['x-poc-expires'] = '2026-11-07T00:00:00Z'
    cases = [('V01', 'No VEX', [], 1),
             ('V02', 'Own not_affected overrides synthetic Block', [('own', document())], 0),
             ('V03', 'Own affected prevents Docker suppression', [('own', document('affected')), ('docker', document())], 1),
             ('V04', 'Own not_affected wins over Docker affected', [('own', document()), ('docker', document('affected'))], 0),
             ('V05', 'Version mismatch', [('own', wrong)], 1),
             ('V06', 'Expired own decision', [('own', expired)], 1),
             ('V07', 'Under investigation prevents lower suppression', [('own', pending), ('docker', document())], 1),
             ('V08', 'Aqua fallback', [('own', wrong), ('docker', wrong), ('aqua', document())], 0),
             ('V09', 'Missing source fails verification', [('own', None)], 2)]
    if args.own_feed_sample:
        cases.append(('V10', 'Actual Debian own feed cannot suppress npm finding', [('own-live', json.loads(Path(args.own_feed_sample).read_text()))], 1))
    evidence = {'type': 'offline_cli_replay_of_real_finding_with_synthetic_policy_and_assessments',
                'actual_finding': {k: actual[k] for k in ['package', 'version', 'id', 'action', 'severity']},
                'synthetic_baseline_action': 'error', 'production_exceptions_created': False, 'cases': []}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'findings.json').write_text(json.dumps([baseline]))
        for case_id, name, sources, expected in cases:
            command = [sys.executable, str(Path(__file__).with_name('socket-vex-evaluate.py')),
                       '--findings', str(root / 'findings.json'), '--product-id', 'urn:socket-poc:dao-voting-ui',
                       '--output', str(root / 'result.json')]
            for index, (source_name, doc) in enumerate(sources):
                source_path = root / f'{case_id}-{index}.json'
                if doc is not None: source_path.write_text(json.dumps(doc))
                command += ['--source', f'{source_name}={source_path}']
            result = subprocess.run(command, capture_output=True, text=True)
            output = json.loads((root / 'result.json').read_text())
            row = {'id': case_id, 'name': name, 'expected_exit': expected, 'actual_exit': result.returncode,
                   'status': 'passed' if result.returncode == expected else 'failed'}
            if output.get('findings'):
                row['selected_vex'] = output['findings'][0].get('vex')
            evidence['cases'].append(row)
            print(f"{case_id}: expected={expected} actual={result.returncode} {row['status']} | {name}")
    Path(args.output).write_text(json.dumps(evidence, indent=2))
    return int(any(x['status'] != 'passed' for x in evidence['cases']))


if __name__ == '__main__':
    raise SystemExit(main())
