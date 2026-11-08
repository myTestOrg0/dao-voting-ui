"""POC OpenVEX overlay for npm findings. Sources are ordered highest priority first.

Used only by the VEX PR variant. Inputs must come from a trusted central source,
not unreviewed PR content. This adapter supports exact npm PURLs, not all OpenVEX
product/identity variants or generic organizational risk acceptances.
"""
import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

STATUSES = {'affected', 'not_affected', 'fixed', 'under_investigation'}
JUSTIFICATIONS = {'component_not_present', 'vulnerable_code_not_present',
                  'vulnerable_code_not_in_execute_path',
                  'vulnerable_code_cannot_be_controlled_by_adversary',
                  'inline_mitigations_already_exist'}


def npm_identity(purl):
    if not isinstance(purl, str) or not purl.startswith('pkg:npm/'):
        return None
    parsed = urlsplit(purl)
    # Qualifiers/subpaths require matching metadata not present in this POC input.
    if parsed.query or parsed.fragment:
        return None
    name, separator, version = purl[len('pkg:npm/'):].rpartition('@')
    if not separator or not name or not version:
        return None
    return unquote(name), unquote(version)


def aliases(value):
    return set(re.findall(r'CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', str(value)))


def parse_time(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('VEX timestamp must include timezone')
    return result


def load_source(name, path, now):
    raw = Path(path).read_bytes()
    document = json.loads(raw)
    if document.get('@context') != 'https://openvex.dev/ns/v0.2.0':
        raise ValueError('Unsupported OpenVEX context')
    if not document.get('@id') or not document.get('author') or not isinstance(document.get('version'), int) or document['version'] < 1:
        raise ValueError('Missing VEX identity, author or version')
    if parse_time(document['timestamp']) > now:
        raise ValueError('VEX document timestamp is in the future')
    if not isinstance(document.get('statements'), list):
        raise ValueError('VEX statements must be an array')
    # Optional organization extension; expiration is not an OpenVEX standard field.
    expired = bool(document.get('x-poc-expires') and parse_time(document['x-poc-expires']) <= now)
    return {'name': name, 'sha256': hashlib.sha256(raw).hexdigest(),
            'document_id': document['@id'], 'expired': expired, 'document': document}


def matching_statement(source, finding, product_id):
    if source['expired']:
        return None
    matches = []
    identity = finding['package'], finding['version']
    ids = aliases(finding['id']) | aliases(finding.get('ghsa', ''))
    for statement in source['document']['statements']:
        vulnerability = statement.get('vulnerability') or {}
        if not ids.intersection(aliases(vulnerability.get('name', '')) | aliases(vulnerability.get('@id', ''))):
            continue
        applicable = False
        for product in statement.get('products') or []:
            top = product.get('@id')
            if npm_identity(top) == identity:
                applicable = True
            if top == product_id:
                applicable |= any(npm_identity(component.get('@id')) == identity
                                  for component in product.get('subcomponents') or [])
        if not applicable:
            continue
        status = statement.get('status')
        if status not in STATUSES:
            raise ValueError('Unknown VEX status for a matching finding')
        if status == 'not_affected' and statement.get('justification') not in JUSTIFICATIONS and not statement.get('impact_statement'):
            raise ValueError('not_affected requires valid justification or impact statement')
        if status == 'affected' and not statement.get('action_statement'):
            raise ValueError('affected requires an action statement')
        matches.append(statement)
    if len({s['status'] for s in matches}) > 1:
        raise ValueError('Conflicting VEX statuses in the same source')
    return matches[0] if matches else None


def evaluate(findings, sources, product_id):
    if any(f.get('action') not in ('error', 'warn', 'monitor', 'ignore') for f in findings):
        raise ValueError('Unrecognized scanner action; VEX cannot turn incomplete verification into success')
    effective = copy.deepcopy(findings)
    for finding in effective:
        finding['original_action'] = finding['action']
        if not finding.get('vulnerability') or finding.get('ecosystem') != 'npm':
            continue
        for source in sources:
            statement = matching_statement(source, finding, product_id)
            if statement is None:
                continue
            finding['vex'] = {'status': statement['status'], 'source': source['name'],
                              'document_id': source['document_id'], 'sha256': source['sha256'],
                              'reason': statement.get('impact_statement') or statement.get('justification') or statement.get('action_statement') or 'Fixed in this product version'}
            if statement['status'] in ('not_affected', 'fixed'):
                finding['action'] = 'ignore'
            # affected/under_investigation stop lower-priority suppressions.
            break
    if any(f['action'] not in ('error', 'warn', 'monitor', 'ignore') for f in effective):
        code = 2
    else:
        code = int(any(f['action'] == 'error' for f in effective))
    return {'exit_code': code, 'findings': effective,
            'sources': [{k: s[k] for k in ('name', 'sha256', 'document_id', 'expired')} for s in sources]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--findings', required=True)
    parser.add_argument('--product-id', required=True)
    parser.add_argument('--source', action='append', default=[], help='NAME=PATH, highest priority first')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        now = datetime.now(timezone.utc)
        sources = [load_source(*item.split('=', 1), now) for item in args.source]
        result = evaluate(json.loads(Path(args.findings).read_text()), sources, args.product_id)
    except (ValueError, KeyError, OSError, TypeError) as error:
        result = {'exit_code': 2, 'verification_complete': False, 'error': str(error)}
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(f"VEX POC effective exit code: {result['exit_code']}")
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
