#!/usr/bin/env python3
"""Offline V5 supplement: preserve V4 notes, replay rescued canonical outputs.

Never replaces the frozen baseline. Only positive height-eligible actual
Ironwood notes enter the delta search; all combinations in its amount interval
are enumerated without shortlist truncation. No target spend/ownership claim.
"""
import hashlib
import json
from pathlib import Path
from collections import defaultdict

from analyze_challenge7_baseline import (dump,write_rows,verified_pending_packets,
    route_link,metadata,payout_txids,route_class,pair_indices,pair_record,pair_count,TARGET,ANCHOR)
from check_challenge7_refund_receiver import BASELINE_SHA
from trace_challenge7_free_near import digest


def make_note(packet,output,links):
    txid=packet['txid'];matched=set(output.get('matchingUnifiedAddresses') or [])
    routes=[r for r in links if r.get('recipient') in matched]
    proof=packet['pendingRequestProvenance']
    if proof.get('txid')!=txid or proof.get('evidenceClass')!='successful-descendant-pending-ID-not-settlement-by-itself':
        raise ValueError('rescued pending provenance mismatch')
    receiver=str(proof.get('requestedReceiver') or '').removeprefix('zcash:')
    return {'id':f"{txid}:ironwood:{output['actionIndex']}:{output['cmx']}",
        'txid':txid,'pool':'ironwood','actionIndex':output['actionIndex'],'cmx':output['cmx'],
        'valueZat':int(output['valueZat']),'valueConfidence':'zero-ovk-decoded-output',
        'receiverBytes':[output['receiverRaw']],'memoHex':output.get('memoHex'),
        'blockHeight':packet['blockHeight'],'blockTime':packet['blockTime'],
        'anchorEligibility':'height-compatible','canonicalBlockHash':packet['canonicalBlockHash'],
        'canonicalMetadataSource':packet['canonicalMetadataSource'],
        'routeRecipientMatched':bool(routes),'routes':routes,**metadata(routes),
        'pendingConnectorProvenance':proof,'pendingConnectorReceiverMatched':bool(receiver and receiver in matched),
        'destinationRole':'requested-route-recipient' if routes else
            'pending-connector-request-recipient-not-complete-execution-proof' if receiver in matched else
            'unattributed-recovered-output-may-be-change'}


def merge(old,new):
    by_id={n['id']:n for n in old};added=[];overlap=[]
    if len(by_id)!=len(old):raise ValueError('duplicate frozen note identity')
    if len({n['id'] for n in new})!=len(new):raise ValueError('duplicate supplemental note identity')
    for note in new:
        if note['blockHeight']>ANCHOR or note['valueZat']<=0 or note['pool']!='ironwood':
            raise ValueError('ineligible supplement note')
        if note['id'] in by_id:
            previous=by_id[note['id']]
            fields=('txid','pool','actionIndex','cmx','valueZat','receiverBytes','blockHeight','blockTime')
            if any(previous[k]!=note[k] for k in fields):raise ValueError('conflicting overlapping actual note')
            overlap.append(note['id'])  # Preserve V4 attribution/bytes; no re-counting.
        else:by_id[note['id']]=note;added.append(note)
    return sorted(by_id.values(),key=lambda n:n['id']),added,overlap


def run():
    repo=Path(__file__).resolve().parents[1]
    baseline=repo/'challenge7-decoded-baseline-v4-data/decoded-notes.jsonl'
    out=repo/'challenge7-decoded-baseline-v5-data'
    if out.is_symlink() or repo not in out.resolve().parents:raise ValueError('output outside repository')
    raw=baseline.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BASELINE_SHA:raise ValueError('frozen V4 baseline changed')
    old=[json.loads(line) for line in raw.splitlines() if line.strip()]
    used={str(baseline):{'sha256':BASELINE_SHA,'bytes':len(raw)}}
    enriched=repo/'challenge7-missing-tree-enriched-data/eligible-decoded-transactions.jsonl'
    packets,audit=verified_pending_packets(enriched,repo/'challenge7-missing-tree-raw-data',used)
    routes_path=repo/'challenge7-complete-routes/all_routes.jsonl';routes_raw=routes_path.read_bytes()
    if hashlib.sha256(routes_raw).hexdigest()!='496a0a49f5d59285d62d125d9a84ba77ecc5791079013f976a943699f5da7c01':
        raise ValueError('frozen quote-route inventory changed')
    used[str(routes_path)]={'sha256':hashlib.sha256(routes_raw).hexdigest(),'bytes':len(routes_raw)}
    links=defaultdict(list);wanted={p['txid'] for p in packets}
    for line in routes_raw.splitlines():
        route=json.loads(line)
        if route_class(route)=='internal-intents':continue
        for txid in set(payout_txids(route))&wanted:links[txid].append(route_link(route))
    supplemental=[]
    for packet in packets:
        for output in packet.get('outputs') or []:
            if output.get('pool')=='ironwood' and output.get('recovered') and int(output.get('valueZat') or 0)>0:
                supplemental.append(make_note(packet,output,links.get(packet['txid'],[])))
    merged,added,overlap=merge(old,supplemental);new_ids={n['id'] for n in added}
    delta_pairs=[pair_record(left,right,TARGET,False) for left,right in pair_indices(merged,TARGET,100000)
                 if left['id'] in new_ids or right['id'] in new_ids]
    counts={'oldNotes':len(old),'eligibleSupplementNotes':len(supplemental),'overlapNotes':len(overlap),
        'newEligibleNotes':len(added),'mergedNotes':len(merged),
        'oldSufficientSingles':sum(n['valueZat']>=TARGET for n in old),
        'mergedSufficientSingles':sum(n['valueZat']>=TARGET for n in merged),
        'newSufficientSingles':sum(n['valueZat']>=TARGET for n in added),
        'oldPairCounts':{str(gap):pair_count(old,TARGET,gap) for gap in (0,1000,10000,100000)},
        'mergedPairCounts':{str(gap):pair_count(merged,TARGET,gap) for gap in (0,1000,10000,100000)},
        'newPairsWithin100000':len(delta_pairs),'newExactPairs':sum(p['possibleChangeZat']==0 for p in delta_pairs),
        'newReceiverLinkedPairs':sum(bool(p['sameDecodedReceiver']) for p in delta_pairs),
        'newMetadataLinkedPairs':sum(bool(p['sameDecodedReceiver']) or any(p['shared'][k] for k in
            ('senders','refunds','fullUnifiedAddresses')) for p in delta_pairs)}
    write_rows(out/'decoded-notes.jsonl',merged);write_rows(out/'new-decoded-notes.jsonl',added)
    write_rows(out/'new-pairs-in-window.jsonl',delta_pairs)
    write_rows(out/'new-structured-pairs.jsonl',[p for p in delta_pairs if p['sameDecodedReceiver'] or
        any(p['shared'][k] for k in ('senders','refunds','fullUnifiedAddresses'))])
    analysis={'completeSupplementReplay':True,'newHttpCalls':0,'challengeSolved':False,
        'targetPrivateSpendLink':False,'enrichmentReplay':audit,'counts':counts,
        'warning':'Positive pre-anchor recovered outputs, not proven available notes or consumed inputs. '
                  'The 100000-zat change interval is a search priority, not exclusion of larger change, '
                  'private intermediaries, opaque notes or historical migrations.'}
    dump(out/'analysis.json',analysis)
    for path,reference in used.items():
        if repo not in Path(path).resolve().parents or digest(Path(path))!=reference['sha256']:
            raise ValueError('input changed/escaped repository during supplement merge')
    names=('analysis.json','decoded-notes.jsonl','new-decoded-notes.jsonl','new-pairs-in-window.jsonl','new-structured-pairs.jsonl')
    dump(out/'manifest.json',{'completeSupplementReplay':True,'newHttpCalls':0,'challengeSolved':False,
        'targetPrivateSpendLink':False,'scriptSha256':digest(Path(__file__)),'inputs':used,
        'artifactHashes':{n:digest(out/n) for n in names}})
    print(json.dumps(analysis,indent=2))


if __name__=='__main__':run()
