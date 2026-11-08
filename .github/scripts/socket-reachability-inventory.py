"""Summarize retained facts and observed upload candidates, never source text."""
import hashlib
import json
import os
from collections import Counter
from pathlib import Path


def main():
    root = Path(os.environ['GITHUB_WORKSPACE'])
    folder = Path(os.environ['SOCKET_RESULTS_DIR']); folder.mkdir(parents=True, exist_ok=True)
    trace = Path(os.environ['SOCKET_TRACE_FILE'])
    events = [json.loads(line) for line in trace.read_text().splitlines() if line.strip()] if trace.exists() else []
    facts_path = root / '.socket.facts.json'
    report = {'engine_version': '15.14.1', 'explicit_production_build_step': False,
              'optional_analytics_disabled': True, 'manifest_uploader_includes_checkout_archive': False,
              'observation_limits': 'Node-launched subprocesses and selected root CLI file streams; not a full network or OS process audit.',
              'upload_candidates': [], 'subprocesses': [e for e in events if e['type']=='subprocess']}
    candidates = {e['path']:e['bytes'] for e in events if e['type']=='cli_file_stream'}
    for name, size in candidates.items():
        report['upload_candidates'].append({'path':name,'bytes':size,
                                            'role':'raw facts read for compression' if name=='.socket.facts.json' else 'root CLI upload candidate'})
    if facts_path.exists():
        raw=facts_path.read_bytes(); data=json.loads(raw)
        fields=Counter(); likely_content=Counter(); filename_count=0
        def walk(value):
            nonlocal filename_count
            if isinstance(value,dict):
                for key,item in value.items():
                    fields[key]+=1
                    normalized=key.lower().replace('_','')
                    if normalized in ('code','sourcecode','sourcecontent','content','snippet','text') and isinstance(item,str) and item:
                        likely_content[key]+=len(item.encode())
                    if key in ('filename','fileName') and isinstance(item,str): filename_count+=1
                    walk(item)
            elif isinstance(value,list):
                for item in value:walk(item)
        walk(data)
        report['facts']={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                         'top_level_keys':list(data) if isinstance(data,dict) else ['array'],
                         'filename_fields':filename_count,'potential_content_field_bytes':dict(likely_content),
                         'field_names':sorted(fields)}
        facts_path.unlink()  # Do not let a later manifest-only scan reuse stale facts.
    else:
        report['facts']={'available':False}
    (folder/'reachability-inventory.json').write_text(json.dumps(report,indent=2))
    print('Reachability data inventory: '+json.dumps({k:v for k,v in report.items() if k not in ('subprocesses',)}))
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:
        stream.write('\n## Reachability data boundary\n\nNo explicit production build step. Engine 15.14.1; optional analytics disabled.\n\n')
        stream.write('| CLI file stream | Bytes | Role |\n|---|---:|---|\n')
        for item in report['upload_candidates']:
            stream.write(f"| {item['path']} | {item['bytes']} | {item['role']} |\n")
        stream.write('\nSee reachability-inventory.json for metadata fields, subprocess categories and observation limits. Raw facts/source text are not uploaded as a GitHub artifact.\n')


if __name__=='__main__':main()
