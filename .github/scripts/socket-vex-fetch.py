"""Load package-specific OpenVEX documents from three immutable GitHub snapshots."""
import hashlib
import importlib.util
import json
import os
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath

spec = importlib.util.spec_from_file_location('vex', __file__.replace('socket-vex-fetch.py', 'socket-vex-evaluate.py'))
vex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex)
ALLOWED = {'myTestOrg0/vexel', 'docker-hardened-images/advisories', 'aquasecurity/vexhub'}
ORDER = ['own', 'docker-dhi', 'aqua']


class GitHubStore:
    """Read public Git snapshots without cross-organization API token permissions."""
    def __init__(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory(prefix='socket-vex-snapshots-')
        self.snapshots = {}

    def git(self, folder, *args):
        import subprocess
        env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
        try:
            result = subprocess.run(['git', '-c', 'credential.helper=', *args], cwd=folder,
                                    capture_output=True, env=env, timeout=180)
        except subprocess.TimeoutExpired:
            raise ValueError('Public VEX snapshot read timed out') from None
        if result.returncode:
            raise ValueError('Unable to read public VEX Git snapshot: ' + args[0])
        return result.stdout

    def resolve(self, repo, ref):
        if repo not in ALLOWED or not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or '..' in ref or ref.startswith('-'):
            raise ValueError('Untrusted repository or invalid VEX ref')
        if repo in self.snapshots and self.snapshots[repo]['ref'] == ref:
            return self.snapshots[repo]['revision']
        from pathlib import Path
        folder = Path(self.temp.name) / repo.replace('/', '--')
        folder.mkdir(exist_ok=True)
        if not (folder / 'HEAD').exists():
            self.git(folder, 'init', '--bare', '--quiet')
            self.git(folder, 'remote', 'add', 'origin', 'https://github.com/' + repo + '.git')
            self.git(folder, 'config', 'remote.origin.promisor', 'true')
            self.git(folder, 'config', 'remote.origin.partialclonefilter', 'blob:none')
        self.git(folder, 'fetch', '--quiet', '--depth=1', '--filter=blob:none', 'origin', ref)
        revision = self.git(folder, 'rev-parse', 'FETCH_HEAD').decode().strip()
        if not re.fullmatch(r'[a-f0-9]{40}', revision):
            raise ValueError('Invalid VEX commit identity')
        self.snapshots[repo] = {'folder': folder, 'ref': ref, 'revision': revision}
        return revision

    def file(self, repo, revision, path):
        if repo not in ALLOWED or not re.fullmatch(r'[a-f0-9]{40}', revision):
            raise ValueError('Untrusted VEX snapshot')
        if '..' in PurePosixPath(path).parts or path.startswith('/'):
            raise ValueError('Invalid VEX document path')
        if repo not in self.snapshots:
            self.resolve(repo, revision)
        raw = self.git(self.snapshots[repo]['folder'], 'show', revision + ':' + path)
        if len(raw) > 10_000_000:
            raise ValueError('VEX document exceeds size limit')
        return raw

    def json_api(self, repo, path):
        # Internal compatibility shape; this uses git ls-tree, not the REST API.
        if repo not in ALLOWED or repo not in self.snapshots:
            raise ValueError('Untrusted or unresolved VEX repository')
        folder = self.snapshots[repo]['folder']
        if path.startswith('contents/pkg?ref='):
            revision = path.split('=', 1)[1]
            raw = self.git(folder, 'ls-tree', revision + ':pkg')
            return [{'name': line.split('\t', 1)[1], 'type': 'dir' if line.startswith('040000') else 'file',
                     'sha': line.split('\t', 1)[0].split()[2]} for line in raw.decode().splitlines()]
        if path.startswith('git/trees/'):
            tree = path[len('git/trees/'):].split('?', 1)[0]
            if not re.fullmatch(r'[a-f0-9]{40}', tree):
                raise ValueError('Invalid package tree identity')
            raw = self.git(folder, 'ls-tree', '-r', tree)
            entries = [{'path': line.split('\t', 1)[1], 'type': line.split()[1]}
                       for line in raw.decode().splitlines()]
            return {'truncated': False, 'tree': entries}
        raise ValueError('Unsupported public snapshot lookup')


def aggregate(name, repo, revision, documents):
    statements, provenance = [], []
    now = datetime.now(timezone.utc)
    for path, raw in documents:
        doc = json.loads(raw)
        if doc.get('@context') != 'https://openvex.dev/ns/v0.2.0' or not doc.get('author') or not doc.get('@id') or not isinstance(doc.get('version'), int):
            raise ValueError('Unsupported or invalid package OpenVEX document')
        if vex.parse_time(doc['timestamp']) > now or not isinstance(doc.get('statements'), list):
            raise ValueError('Invalid OpenVEX timestamp or statements')
        expired = bool(doc.get('x-poc-expires') and vex.parse_time(doc['x-poc-expires']) <= now)
        provenance.append({'path': path, 'id': doc['@id'], 'sha256': hashlib.sha256(raw).hexdigest(), 'expired': expired})
        if not expired:
            statements.extend(doc['statements'])
    digest = hashlib.sha256(json.dumps(provenance, sort_keys=True).encode()).hexdigest()
    return {'name': name, 'sha256': digest, 'document_id': f'https://github.com/{repo}/tree/{revision}',
            'expired': False, 'document': {'statements': statements}, 'documents': provenance, 'revision': revision, 'repository': repo}


def load_sources(config, findings, store=None):
    store = store or GitHubStore()
    if [s['name'] for s in config['sources']] != ORDER:
        raise ValueError('Expected priority own → docker-dhi → aqua')
    required = {f['package'] for f in findings if f.get('ecosystem') == 'npm' and f.get('vulnerability')}
    sources = []
    for item in config['sources']:
        repo = item['repository']
        revision = store.resolve(repo, item['ref'])
        metadata = json.loads(store.file(repo, revision, 'vex-repository.json'))
        if not any(v.get('spec_version') == '0.1' for v in metadata.get('versions', [])):
            raise ValueError('Unsupported VEX repository specification')
        root = store.json_api(repo, 'contents/pkg?ref=' + revision)
        npm = next((x for x in root if x.get('name') == 'npm' and x.get('type') == 'dir'), None)
        documents = []
        if npm:
            tree = store.json_api(repo, 'git/trees/' + npm['sha'] + '?recursive=1')
            if tree.get('truncated'):
                raise ValueError('Incomplete package index; cannot conclude no applicable VEX')
            for entry in tree['tree']:
                if entry['type'] != 'blob' or not entry['path'].endswith('.json'):
                    continue
                relative = PurePosixPath(entry['path'])
                # The repository layout uses URL-encoded namespace/name segments.
                from urllib.parse import unquote
                package = '/'.join(unquote(p) for p in relative.parts[:-1])
                if package not in required or relative.name == 'manifest.json':
                    continue
                path = 'pkg/npm/' + entry['path']
                documents.append((path, store.file(repo, revision, path)))
        source = aggregate(item['name'], repo, revision, documents)
        source['npm_coverage'] = bool(npm)
        sources.append(source)
        print(f"VEX source {item['name']}: commit={revision}, applicable-package documents={len(documents)}, npm index={bool(npm)}")
    return sources
