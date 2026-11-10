"""Fetch trusted OpenVEX feeds only when their product scope is eligible."""
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from socket_vex import parse_source


REPOSITORIES = {
    'own': 'myTestOrg0/vexel',
    'docker-dhi': 'docker-hardened-images/advisories',
    'aqua': 'aquasecurity/vexhub',
}
SCOPES = {
    'own': {'manifest', 'application', 'image', 'dhi-image'},
    'docker-dhi': {'dhi-image'},
    'aqua': {'image', 'dhi-image'},
}


class GitHubStore:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='socket-vex-')
        self.snapshots = {}

    def git(self, repo, *args):
        folder = Path(self.temp.name) / repo.replace('/', '--')
        folder.mkdir(exist_ok=True)
        env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
        env.pop('SOCKET_SECURITY_API_KEY', None)
        try:
            result = subprocess.run(['git', '-c', 'credential.helper=', *args], cwd=folder,
                                    env=env, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            raise ValueError('VEX Git request timed out') from None
        if result.returncode:
            raise ValueError(f'Cannot read trusted VEX snapshot: {repo}')
        return result.stdout

    def resolve(self, repo, ref):
        if repo not in REPOSITORIES.values() or not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or '..' in ref or ref.startswith('-'):
            raise ValueError('Untrusted VEX repository or ref')
        if repo not in self.snapshots:
            self.git(repo, 'init', '--bare', '--quiet')
            self.git(repo, 'remote', 'add', 'origin', 'https://github.com/' + repo + '.git')
            self.git(repo, 'config', 'remote.origin.promisor', 'true')
            self.git(repo, 'config', 'remote.origin.partialclonefilter', 'blob:none')
            self.git(repo, 'fetch', '--quiet', '--depth=1', '--filter=blob:none', 'origin', ref)
            self.snapshots[repo] = self.git(repo, 'rev-parse', 'FETCH_HEAD').decode().strip()
            if not re.fullmatch(r'[a-f0-9]{40}', self.snapshots[repo]):
                raise ValueError('Invalid VEX commit identity')
        return self.snapshots[repo]

    def file(self, repo, revision, path):
        if repo not in self.snapshots or revision != self.snapshots[repo] or '..' in PurePosixPath(path).parts or path.startswith('/'):
            raise ValueError('Invalid VEX snapshot path')
        raw = self.git(repo, 'show', revision + ':' + path)
        if len(raw) > 10_000_000:
            raise ValueError('VEX document exceeds size limit')
        return raw


def load_sources(config, findings, target, store=None):
    if target not in SCOPES['own']:
        raise ValueError('Unknown VEX product scope')
    if [item['name'] for item in config['sources']] != list(REPOSITORIES):
        raise ValueError('Expected VEX priority own → Docker DHI → Aqua')
    required = {row['package'] for row in findings if row['vulnerability'] and row['ecosystem'] == 'npm'}
    store = store or GitHubStore()
    sources = []
    for item in config['sources']:
        name, repo = item['name'], item['repository']
        if repo != REPOSITORIES[name]:
            raise ValueError('Unexpected repository for VEX source')
        source = {'name': name, 'repository': repo, 'eligible': target in SCOPES[name],
                  'revision': None, 'documents': [], 'expired': False, 'document': {'statements': []}}
        if not source['eligible']:
            source['reason'] = f'{name} requires {", ".join(sorted(SCOPES[name]))}; this scan targets {target}'
            sources.append(source)
            continue
        revision = store.resolve(repo, item['ref'])
        metadata = json.loads(store.file(repo, revision, 'vex-repository.json'))
        if not any(version.get('spec_version') == '0.1' for version in metadata.get('versions', [])):
            raise ValueError('Unsupported VEX repository specification')
        tree = store.git(repo, 'ls-tree', '-r', '--name-only', revision, 'pkg/npm').decode().splitlines()
        for path in tree:
            relative = PurePosixPath(path)
            package = '/'.join(unquote(part) for part in relative.parts[2:-1])
            if relative.suffix != '.json' or relative.name == 'manifest.json' or package not in required:
                continue
            doc = parse_source(name, store.file(repo, revision, path), datetime.now(timezone.utc))
            source['documents'].append({'path': path, 'id': doc['document_id'], 'sha256': doc['sha256'], 'expired': doc['expired']})
            if not doc['expired']:
                source['document']['statements'].extend(doc['document']['statements'])
        source.update(revision=revision, document_id=f'https://github.com/{repo}/tree/{revision}',
                      sha256=hashlib.sha256(json.dumps(source['documents'], sort_keys=True).encode()).hexdigest())
        sources.append(source)
    return sources
