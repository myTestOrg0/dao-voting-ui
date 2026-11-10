import json, os
from socket_scan import get_api
from pathlib import Path
org='lido-labs'
repo=json.loads(get_api(org,'repos/dao-voting-ui'))
print('Repository fields:',sorted(repo))
print('Repository heads:',json.dumps({k:v for k,v in repo.items() if 'head' in k or 'branch' in k},indent=2))
for ident in ('5ad206bd-4929-42c8-b847-e30934df2e01','dbcc993e-98da-4322-ac04-c77e8e80044b'):
    meta=json.loads(get_api(org,'full-scans/'+ident+'/metadata'))
    print('Metadata',ident,json.dumps({k:meta.get(k) for k in ('id','scan_type','branch','commit_hash','created_at','scan_state')},indent=2))
