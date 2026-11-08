"""Run explicitly synthetic priority fixtures stored in the central VEX repository."""
import importlib.util
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

spec = importlib.util.spec_from_file_location('fetch', Path(__file__).with_name('socket-vex-fetch.py'))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


def main():
    config = json.loads(Path('.github/socket-vex-sources.json').read_text())['sources'][0]
    store = fetch.GitHubStore()
    revision = store.resolve(config['repository'], config['ref'])
    index = json.loads(store.file(config['repository'], revision, 'poc/socket/priority-cases.json'))
    if index.get('synthetic') is not True or index['product_id'] != 'urn:socket-poc:priority-test':
        raise ValueError('Central tests must be isolated synthetic fixtures')
    result = {'synthetic': True, 'repository': config['repository'], 'revision': revision, 'cases': []}
    with TemporaryDirectory() as directory:
        for case in index['cases']:
            sources = []
            for i, item in enumerate(case['sources']):
                if not item['path'].startswith('poc/socket/fixtures/'):
                    raise ValueError('Test document path is not isolated')
                raw = store.file(config['repository'], revision, item['path'])
                path = Path(directory) / f'{case["id"]}-{i}.json'
                path.write_bytes(raw)
                sources.append(fetch.vex.load_source(item['name'], path, datetime.now(timezone.utc)))
            actual = fetch.vex.evaluate([index['finding']], sources, index['product_id'])['exit_code']
            row = {'id': case['id'], 'name': case['name'], 'expected': case['expected_exit'], 'actual': actual,
                   'passed': actual == case['expected_exit']}
            result['cases'].append(row)
            print('Central VEX fixture: ' + json.dumps(row))
    folder = Path(os.environ['SOCKET_RESULTS_DIR']); folder.mkdir(parents=True, exist_ok=True)
    (folder / 'central-priority-tests.json').write_text(json.dumps(result, indent=2))
    return int(not all(c['passed'] for c in result['cases']))


if __name__ == '__main__':
    raise SystemExit(main())
