"""Load package-specific OpenVEX documents from three immutable GitHub snapshots."""
import hashlib
import importlib.util
import json
import os
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('vex', __file__.replace('socket-vex-fetch.py', 'socket-vex-evaluate.py'))
vex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex)
ALLOWED = {'myTestOrg0/vexel', 'docker-hardened-images/advisories', 'aquasecurity/vexhub'}
ORDER = ['own', 'docker-dhi', 'aqua']


class GitHubStore:
    def __init__(self):
        self.cache = {}

    def get(self, url, optional=False):
        if url in self.cache:
            return self.cache[url]
        headers = {'User-Agent': 'Socket-POC-VEX'}
        token = os.environ.get('GITHUB_TOKEN')
        if token and url.startswith('https://api.github.com/'):
            headers['Authorization'] = 'Bearer ' + token
        try:
            with urlopen(Request(url, headers=headers), timeout=45) as response:
                value = response.read(10_000_001)
                if len(value) > 10_000_000:
                    raise ValueError('VEX response exceeds size limit')
        except HTTPError as error:
            if error.code == 404 and optional:
                return None
            raise ValueError(f'Verified VEX source request failed: HTTP {error.code}') from None
        self.cache[url] = value
        return value

    def json_api(self, repo, path):
        if repo not in ALLOWED:
            raise ValueError('Untrusted VEX repository')
        return json.loads(self.get('https://api.github.com/repos/' + repo + '/' + path))

    def resolve(self, repo, ref):
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or '..' in ref:
            raise ValueError('Invalid VEX ref')
        if re.fullmatch(r'[a-f0-9]{40}', ref):
            return ref
        return self.json_api(repo, 'commits/' + quote(ref, safe=''))['sha']

    def file(self, repo, revision, path):
        if repo not in ALLOWED or not re.fullmatch(r'[a-f0-9]{40}', revision):
            raise ValueError('Untrusted VEX snapshot')
        if '..' in PurePosixPath(path).parts or path.startswith('/'):
            raise ValueError('Invalid VEX document path')
        return self.get(f'https://raw.githubusercontent.com/{repo}/{revision}/' + quote(path, safe='/'))


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
