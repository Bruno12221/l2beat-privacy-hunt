#!/usr/bin/env python3
"""Close declared missing-root requests using hash-checked local full trees first.

Offline by default. --fetch enables bounded sequential public FastNear read-only
POSTs (20 roots/batch), preserving original response bodies. No JWT or Dune.
Pending identifiers are not mined payouts, private spends, or wallet ownership.
"""
import argparse
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path

from analyze_challenge7_baseline import dump,write_rows
from audit_challenge7_connector_ids import full_tree_rpc_result,rpc_pending_ids
from trace_challenge7_free_near import digest,API
from trace_challenge7_user_origins import Reader


def inside(repo,path):
    path=Path(path)
    if path.is_symlink() or repo not in path.resolve().parents:
        raise ValueError('evidence path outside hunt repository')
    return path


def entries(value,wanted):
    result={}
    if not isinstance(value,dict) or not isinstance(value.get('transactions'),list):
        raise ValueError('full-tree API response schema mismatch')
    for entry in value['transactions']:
        root=(entry.get('transaction') or {}).get('hash')
        if root not in wanted or root in result:
            raise ValueError('unrequested or duplicate full-tree root')
        result[root]=entry
    return result


def audit_request(request,entry,reference):
    root=(entry.get('transaction') or {}).get('hash')
    if root!=request['nearRoot']:raise ValueError('request/tree root identity mismatch')
    try:
        result=full_tree_rpc_result(entry)
        pending,error=rpc_pending_ids(result,request['listedReceiptId'])
    except ValueError as exc:
        pending=[];error='full-tree-validation: '+str(exc)
    return {**request,'originalMissingReason':request['error'],'error':error,
        'treeChecked':True,'source':reference,'pendingIdentifiers':pending,
        'explicitPendingIdentifierRecovered':bool(pending),'settlementProven':False,
        'targetPrivateSpendLink':False}


def run(args):
    repo=Path(__file__).resolve().parents[1]
    src=repo/'challenge7-connector-id-audit-v2-data'
    out=inside(repo,repo/'challenge7-missing-tree-rescue-data');out.mkdir(exist_ok=True)
    manifest_path=src/'manifest.json';missing_path=src/'unresolved-requests.jsonl'
    raw_requests=repo/'challenge7-free-raw-rescue-data/combined-raw-withdrawals.jsonl'
    used={str(p):digest(p) for p in (manifest_path,missing_path,raw_requests)}
    old_manifest=json.loads(manifest_path.read_text())
    if used[str(raw_requests)]!=old_manifest['requestsSha256']:
        raise ValueError('frozen original request inventory changed')
    unresolved=[json.loads(line) for line in missing_path.read_text().splitlines()]
    if (len(unresolved)!=old_manifest['unresolvedRequests'] or
            dict(Counter(r['error'] for r in unresolved))!=old_manifest['unresolvedReasons']):
        raise ValueError('unresolved inventory/manifest disagreement')
    selected=[r for r in unresolved if r['error']=='RPC-root-cache-missing']
    originals={}
    for line in raw_requests.open():
        row=json.loads(line);originals[(row['nearTransactionHash'],row['receiptId'])]=row
    if any((r['nearRoot'],r['listedReceiptId']) not in originals for r in selected):
        raise ValueError('missing request not in the frozen original inventory')
    by_root={r['nearRoot']:r for r in selected}
    if len(by_root)!=len(selected):raise ValueError('selected scope needs explicit multiple-receipt grouping')
    roots={};references={};reader=Reader(out,args.fetch,args.max_http_calls,1.1)
    db_path=inside(repo,repo/'challenge7-withdrawal-ledger-data/ledger.sqlite3')
    db=sqlite3.connect('file:'+str(db_path.resolve())+'?mode=ro',uri=True)
    cached_files={}
    try:
        for root in sorted(by_root):
            found=db.execute('SELECT data FROM roots WHERE hash=? AND done=1 AND complete=1',(root,)).fetchone()
            if found is None:continue
            path=inside(repo,json.loads(found[0])['sourceResponse'])
            expected=db.execute('SELECT sha256 FROM responses WHERE path=?',(str(path),)).fetchone()
            if expected is None:raise ValueError('completed local tree has no response hash')
            if str(path) not in cached_files:
                if digest(path)!=expected[0]:raise ValueError('local full-tree source SHA mismatch')
                value=json.loads(path.read_text())
                cached_files[str(path)]=value.get('transactions') or []
                used[str(path)]=expected[0]
            matching=[e for e in cached_files[str(path)] if (e.get('transaction') or {}).get('hash')==root]
            if len(matching)!=1:raise ValueError('exact completed tree missing/duplicated in local response')
            roots[root]=matching[0];references[root]={'path':str(path),'sha256':expected[0],
                'kind':'hash-checked-completed-local-tree','originalTransportBytesAsserted':False}
    finally:db.close()
    local_roots=len(roots);missing=sorted(set(by_root)-set(roots));stopped=None
    for start in range(0,len(missing),20):
        batch=missing[start:start+20]
        try:
            response=reader.request(API,{'tx_hashes':batch})
            returned=entries(response,set(batch))
            for root,entry in returned.items():
                roots[root]=entry;references[root]={**reader.index[-1],
                    'kind':'original-public-fastnear-response','originalTransportBytesAsserted':True}
            if set(returned)!=set(batch):
                stopped='not all requested roots returned; absent roots remain unresolved';break
            print('full trees='+str(len(roots))+'/'+str(len(by_root))+' new_HTTP='+str(reader.calls),flush=True)
        except Exception as exc:
            stopped=str(exc);break  # No retries or provider rotation on API/transport failures.
    results=[];pending=[];new_pending=[]
    old_pending_path=src/'pending-ids.jsonl';used[str(old_pending_path)]=digest(old_pending_path)
    if used[str(old_pending_path)]!=old_manifest['pendingIdsSha256']:raise ValueError('old pending-ID ledger changed')
    old_ids={json.loads(line)['txid'] for line in old_pending_path.open()}
    for root,request in sorted(by_root.items()):
        if root in roots:
            result=audit_request(request,roots[root],references[root]);results.append(result)
            origin=originals[(root,request['listedReceiptId'])]
            for event in result['pendingIdentifiers']:
                row={**event,'nearRoot':root,'listedReceiptId':request['listedReceiptId'],
                    'requestedReceiver':origin.get('targetAddress'),'nearTime':origin.get('blockTime'),
                    'source':references[root],'newToOriginalPendingInventory':event['txid'] not in old_ids,
                    'evidenceClass':'successful-descendant-pending-ID-not-settlement-by-itself',
                    'settlementProven':False,'targetPrivateSpendLink':False}
                pending.append(row)
                if row['newToOriginalPendingInventory']:new_pending.append(row)
        else:
            results.append({**request,'treeChecked':False,'explicitPendingIdentifierRecovered':False,
                            'settlementProven':False,'targetPrivateSpendLink':False})
    remaining=[r for r in results if r.get('error')]
    analysis={'declaredMissingRoots':len(by_root),'reusedCompleteLocalTrees':local_roots,
        'fullTreesAvailable':len(roots),'newHttpCalls':reader.calls,
        'explicitPendingEvents':len(pending),'distinctPendingIds':len({r['txid'] for r in pending}),
        'newDistinctPendingIds':len({r['txid'] for r in new_pending}),
        'selectedRequestsStillUnresolved':len(remaining),
        'selectedRequestsWithPendingIdentifier':sum(r['explicitPendingIdentifierRecovered'] for r in results),
        'remainingSelectedReasons':dict(Counter(r['error'] for r in remaining)),
        'unselectedOriginalUnresolvedRequests':len(unresolved)-len(selected),
        'stopped':stopped,'challengeSolved':False,'targetPrivateSpendLink':False,
        'warning':'Only original missing-root requests checked. Tree/descendant pending identity is '
                  'not settlement, canonical height, plaintext output, ownership or private consumption.'}
    write_rows(out/'request-results.jsonl',results);write_rows(out/'pending-ids.jsonl',pending)
    write_rows(out/'new-pending-ids.jsonl',new_pending);write_rows(out/'unresolved-requests.jsonl',remaining)
    dump(out/'analysis.json',analysis)
    for path,sha in used.items():
        if digest(inside(repo,path))!=sha:raise ValueError('frozen source changed during audit')
    dump(out/'manifest.json',{'declaredMissingRootAuditComplete':len(roots)==len(by_root) and stopped is None,
        'selectedPendingCoverageComplete':not remaining,'newHttpCalls':reader.calls,'stopped':stopped,
        'challengeSolved':False,'targetPrivateSpendLink':False,'scriptSha256':digest(Path(__file__)),
        'frozenInputHashes':used,'responsesUsed':reader.index,'artifactHashes':{n:digest(out/n) for n in
            ('analysis.json','request-results.jsonl','pending-ids.jsonl','new-pending-ids.jsonl','unresolved-requests.jsonl')}})
    print(json.dumps(analysis,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch',action='store_true')
    parser.add_argument('--max-http-calls',type=int,default=10)
    args=parser.parse_args()
    if args.max_http_calls<0:parser.error('request cap must be nonnegative')
    run(args)
