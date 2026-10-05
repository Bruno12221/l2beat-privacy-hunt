#!/usr/bin/env python3
"""Offline audit of the specific outgoing collector, with exact typed receivers.

No network, JWT, parent-directory search, ownership inference or private spend proof.
"""
import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from analyze_challenge7_baseline import dump, write_rows, atomic_write
from collect_challenge7_outgoing_quotes import validate_page, stamp, ALL_STATUSES, API
from check_challenge7_quote_receiver_reuse import target_evidence, decode_batch, typed_receivers, matching_types, time_class
from check_challenge7_refund_receiver import BASELINE_SHA, DEPOSIT, DESTINATION
from trace_challenge7_free_near import digest

FIELDS=('refundTo','recipient','depositAddress','virtualChainRecipient','virtualChainRefundRecipient')
KEEP=('createdAt','depositAddress','depositMemo','originAsset','destinationAsset','recipient',
      'refundTo','status','referral','amountIn','amountOut','originChainTxHashes',
      'destinationChainTxHashes','nearTxHashes','senders')
BASELINE_V5_SHA='34ad8fa5343def6c330598659e50d93b38a84e2a37f6a5c50aeac121aa41448b'


def note_baseline(repo,v5=False):
    path=repo/('challenge7-decoded-baseline-v5-data' if v5 else 'challenge7-decoded-baseline-v4-data')/'decoded-notes.jsonl'
    expected=BASELINE_V5_SHA if v5 else BASELINE_SHA
    if path.is_symlink() or repo not in path.resolve().parents or digest(path)!=expected:
        raise ValueError('frozen actual-note baseline changed/escaped repository')
    if v5:
        manifest=json.loads((path.parent/'manifest.json').read_text())
        previous=str(repo/'challenge7-decoded-baseline-v4-data/decoded-notes.jsonl')
        if (not manifest.get('completeSupplementReplay') or
                manifest['artifactHashes']['decoded-notes.jsonl']!=expected or
                manifest['inputs'][previous]['sha256']!=BASELINE_SHA):
            raise ValueError('V5 supplement manifest incomplete or inconsistent')
    return path


def page_source(path,expected_statuses=ALL_STATUSES):
    raw=path.read_bytes();e=json.loads(raw);body=e['rawUtf8'].encode()
    if (e['request'] is not None or e['httpStatus']!=200
            or hashlib.sha256(body).hexdigest()!=e['responseBytesSha256']
            or json.loads(body)!=e['response']):raise ValueError('source envelope integrity mismatch')
    u=urlparse(e['url']);params=parse_qs(u.query,keep_blank_values=True)
    if u.scheme+'://'+u.netloc+u.path!=API or any(len(v)!=1 for v in params.values()):
        raise ValueError('wrong endpoint or ambiguous query')
    q={k:v[0] for k,v in params.items()}
    required={'numberOfTransactions':'1000','direction':'next','fromChainId':'zec','statuses':expected_statuses}
    if any(q.get(k)!=v for k,v in required.items()) or set(q)-{
            *required,'startTimestamp','endTimestamp','lastDepositAddress','lastDepositMemo'}:
        raise ValueError('unexpected collector query/filter')
    state={'windowStart':q['startTimestamp'],'windowEnd':q['endTimestamp'],
           'lastDepositAddress':q.get('lastDepositAddress'),'lastDepositMemo':q.get('lastDepositMemo'),
           'scope':{'statuses':expected_statuses}}
    rows=validate_page(e['response'],state)
    if path.name!=hashlib.sha256(e['url'].encode()).hexdigest()+'.json':
        raise ValueError('URL/cache filename mismatch')
    return rows,state,{'path':str(path.resolve()),'sha256':hashlib.sha256(raw).hexdigest(),
                       'responseBodySha256':e['responseBytesSha256'],'url':e['url'],'rows':len(rows)}


def window_chain(pages):
    by_cursor={}
    for state,rows,source in pages:
        key=(state.get('lastDepositAddress'),state.get('lastDepositMemo'))
        if key in by_cursor:raise ValueError('duplicate cursor page')
        by_cursor[key]=(rows,source)
    cursor=(None,None);seen=set();count=0;previous=None;complete=False
    while cursor in by_cursor:
        if cursor in seen:raise ValueError('pagination cycle')
        seen.add(cursor);rows,source=by_cursor[cursor];count+=len(rows)
        if previous and rows and stamp(rows[0]['createdAt'])>previous:
            raise ValueError('page boundary moves forward in time')
        if rows:previous=stamp(rows[-1]['createdAt'])
        if len(rows)<1000:complete=True;break
        cursor=(rows[-1]['depositAddress'],rows[-1].get('depositMemo'))
    if len(seen)!=len(pages):raise ValueError('unreachable cached pages')
    return {'pages':len(seen),'rowOccurrences':count,'exhausted':complete,
            'missingNextCursor':None if complete else list(cursor)}


def exhausted_intervals(windows):
    """Merge only exhausted queries; touching exclusive bounds leave a point gap."""
    spans=sorted((stamp(w['start']),stamp(w['end'])) for w in windows if w['exhausted'])
    merged=[]
    for start,end in spans:
        if merged and start<merged[-1][1]:merged[-1][1]=max(end,merged[-1][1])
        else:merged.append([start,end])
    return [{'startExclusive':start.isoformat(),'endExclusive':end.isoformat(),
             'durationSeconds':(end-start).total_seconds()} for start,end in merged]


def live_snapshot(repo,src):
    """Copy a stable accepted-page checkpoint; never stop/edit the collector.

    A snapshot's manifest is explicitly derived from the checkpoint, not a
    claim that a still-running collector wrote its terminal manifest.
    """
    repo=repo.resolve()
    if src.is_symlink() or repo not in src.resolve().parents:raise ValueError('source outside repository')
    checkpoint_raw=(src/'checkpoint.json').read_bytes();checkpoint=json.loads(checkpoint_raw)
    paths=sorted((src/'http-responses').glob('*.json'));payloads=[];rows=0
    for path in paths:
        if path.is_symlink():raise ValueError('source symlink not allowed')
        raw=path.read_bytes();value=json.loads(raw)
        # Independently validate bytes and the requested scope before copying.
        checked=page_source(path,checkpoint['scope']['statuses'])[0]
        if checked!=value['response']:raise ValueError('response changed during snapshot')
        rows+=len(checked);payloads.append((path.name,raw))
    if len(paths)!=checkpoint['successfulPages'] or rows!=checkpoint['rowOccurrences']:
        raise ValueError('collector saving a page; retry snapshot without stopping it')
    if (src/'checkpoint.json').read_bytes()!=checkpoint_raw or sorted((src/'http-responses').glob('*.json'))!=paths:
        raise ValueError('collector advanced during snapshot; retry without stopping it')
    root=repo/'challenge7-outgoing-nonpending-snapshots'/hashlib.sha256(checkpoint_raw).hexdigest()
    if root.is_symlink() or repo not in root.resolve().parents:raise ValueError('snapshot outside repository')
    target=root/'collection'
    if target.is_symlink() or repo not in target.resolve().parents:raise ValueError('snapshot collection outside repository')
    for name,raw in payloads:
        destination=target/'http-responses'/name
        if destination.is_symlink() or repo not in destination.resolve().parents:
            raise ValueError('snapshot response outside repository')
        atomic_write(destination,raw.decode())
    atomic_write(target/'checkpoint.json',checkpoint_raw.decode())
    dump(target/'manifest.json',{'scope':checkpoint['scope'],'retrievalComplete':False,
        'stopped':'read-only accepted-page checkpoint snapshot; terminal collector completion not asserted',
        'successfulPages':checkpoint['successfulPages'],'rowOccurrences':checkpoint['rowOccurrences'],
        'challengeSolved':False,'snapshot':True,'originalCollectorDirectory':str(src),
        'originalCheckpointSha256':hashlib.sha256(checkpoint_raw).hexdigest()})
    return target,root/'analysis'


def main(nonpending=False,source=None,output=None,baseline_v5=False):
    repo=Path(__file__).resolve().parents[1]
    src=source or repo/('challenge7-outgoing-nonpending-collection' if nonpending else 'challenge7-outgoing-quote-collection')
    out=output or repo/('challenge7-outgoing-nonpending-analysis' if nonpending else 'challenge7-outgoing-collection-analysis')
    if src.is_symlink() or out.is_symlink() or any(repo not in p.resolve().parents for p in (src,out)):
        raise ValueError('output/source must remain inside repository without symlinks')
    checkpoint=json.loads((src/'checkpoint.json').read_text());cm=json.loads((src/'manifest.json').read_text())
    source_pins={name:digest(src/name) for name in ('checkpoint.json','manifest.json')}
    if checkpoint['scope']!=cm['scope']:raise ValueError('collector scope disagreement')
    expected_statuses=cm['scope']['statuses']
    wanted='FAILED,INCOMPLETE_DEPOSIT,PROCESSING,REFUNDED,SUCCESS' if nonpending else ALL_STATUSES
    if expected_statuses!=wanted:raise ValueError('input status scope is not the selected analysis scope')
    target=target_evidence(repo,repo/'decoder/target/release/unified_receivers')
    baseline=note_baseline(repo,baseline_v5)
    notes_by_receiver=defaultdict(list);notes=[]
    for line in baseline.open():
        n=json.loads(line);notes.append(n)
        kind={'ironwood':'orchard','orchard':'orchard','sapling':'sapling'}.get(n['pool'])
        if not kind:raise ValueError('unknown recovered-note receiver type')
        for receiver in n['receiverBytes']:notes_by_receiver[(kind,receiver.lower())].append(n['id'])
    paths=sorted((src/'http-responses').glob('*.json'));inventory=[];windows=defaultdict(list)
    counts=Counter();refund_prefixes=Counter();refs=Counter();identities=set();seen_rows=set()
    ua_occurrences=[];executed=[];target_dest=[];earliest=None;latest=None
    for index,path in enumerate(paths,1):
        if path.is_symlink() or repo not in path.resolve().parents:raise ValueError('source outside repository')
        rows,state,source=page_source(path,expected_statuses);inventory.append(source)
        windows[(state['windowStart'],state['windowEnd'])].append((state,rows,source))
        for i,row in enumerate(rows):
            counts[row['status']]+=1;refs[str(row.get('referral'))]+=1
            refund_prefixes[str(row.get('refundTo',''))[:3]]+=1
            t=stamp(row['createdAt']);earliest=min(t,earliest) if earliest else t;latest=max(t,latest) if latest else t
            identities.add((row['depositAddress'],row.get('depositMemo'),row['createdAt']))
            rh=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            if rh in seen_rows:continue
            seen_rows.add(rh)
            entry={'source':source['path'],'sourceSha256':source['sha256'],'rowIndex':i,
                   'rowCanonicalSha256':rh,'metadata':{k:row.get(k) for k in KEEP},
                   'isTargetSelf':row['depositAddress']==DEPOSIT,'evidenceClass':'API quote metadata only',
                   'ownershipProven':False,'targetPrivateSpendLink':False}
            if row['status'] in ('SUCCESS','REFUNDED') or row.get('originChainTxHashes'):executed.append(entry)
            if str(row.get('recipient','')).lower()==DESTINATION.lower():target_dest.append(entry)
            for field in FIELDS:
                addr=row.get(field)
                if isinstance(addr,str) and addr.lower().startswith('u1'):
                    ua_occurrences.append({**entry,'field':field,'address':addr})
        if index%25==0:print('validated pages='+str(index)+'/'+str(len(paths)),flush=True)
    if (len(paths)!=checkpoint['successfulPages'] or sum(s['rows'] for s in inventory)!=checkpoint['rowOccurrences']
            or cm['successfulPages']!=len(paths) or cm['rowOccurrences']!=sum(counts.values())):
        raise ValueError('saved-page/checkpoint counts disagree')
    coverage=[]
    for (start,end),pages in sorted(windows.items()):
        coverage.append({'start':start,'end':end,**window_chain(pages)})
    addresses=sorted({o['address'] for o in ua_occurrences});decoded=[]
    for offset in range(0,len(addresses),500):
        decoded.extend(decode_batch(addresses[offset:offset+500],repo/'decoder/target/release/unified_receivers'))
        print('decoded='+str(len(decoded))+'/'+str(len(addresses)),flush=True)
    by_address={d['address']:d['decode'] for d in decoded};target_matches=[];note_matches=[]
    for occurrence in ua_occurrences:
        d=by_address[occurrence['address']];types=matching_types(d,target['receivers'])
        if types:target_matches.append({**occurrence,'receiverTypesMatched':types,
            'timing':time_class(occurrence['metadata']['createdAt'],target['quoteTimestamp'])})
        for kind,raw in typed_receivers(d).items():
            noteids=notes_by_receiver.get((kind,raw))
            if noteids:note_matches.append({**occurrence,'receiverKind':kind,'receiverRaw':raw,
                                           'matchedBaselineNoteIds':noteids})
    invalid=[d for d in decoded if not d['decode']['ok']]
    analysis={'offlineAuditComplete':True,'newHttpCalls':0,'retrievalCompleteReported':cm['retrievalComplete'],
        'collectorStopped':cm['stopped'],'scope':cm['scope'],'checkpoint':checkpoint,'coverageWindows':coverage,
        'sourcePages':len(paths),'rowOccurrences':sum(counts.values()),'uniqueQuoteIdentityKeys':len(identities),
        'uniqueCanonicalRows':len(seen_rows),'statusOccurrences':dict(counts),'referralOccurrences':dict(refs),
        'refundPrefixOccurrences':dict(refund_prefixes),'oldestSavedCreatedAt':earliest.isoformat() if earliest else None,
        'newestSavedCreatedAt':latest.isoformat() if latest else None,'target':target,'targetDepositPresent':any(o['isTargetSelf'] for o in executed),
        'targetDestinationOccurrences':len(target_dest),'uniqueUnifiedStrings':len(addresses),
        'validMainnetUnifiedStrings':sum(d['decode']['ok'] and d['decode'].get('network')=='Main' for d in decoded),
        'invalidUnifiedStrings':len(invalid),'targetReceiverMatchOccurrences':len(target_matches),
        'nonTargetReceiverMatchOccurrences':sum(not m['isTargetSelf'] for m in target_matches),
        'targetReceiverMatchesByStatus':dict(Counter(m['metadata']['status'] for m in target_matches)),
        'baselineNotes':len(notes),'noteReceiverMatchOccurrences':len(note_matches),
        'distinctMatchedBaselineNotes':len({n for m in note_matches for n in m['matchedBaselineNoteIds']}),
        'noteReceiverMatchesByStatus':dict(Counter(m['metadata']['status'] for m in note_matches)),
        'noteReceiverMatchesByField':dict(Counter(m['field'] for m in note_matches)),
        'distinctNoteMatchQuoteIdentityKeys':len({(m['metadata']['depositAddress'],m['metadata']['depositMemo'],
                                                 m['metadata']['createdAt']) for m in note_matches}),
        'distinctNoteMatchReceivers':len({(m['receiverKind'],m['receiverRaw']) for m in note_matches}),
        'workingCandidateReceiverMatchOccurrences':sum(m['receiverRaw']==
            'dc98cff1b7a3d2bfbc6088e9cb9d57b572a1aa1c7e1b44a868ed7757b79c6db355e63dd0711c0acfb2ce32'
            for m in note_matches),
        'targetPrivateSpendLink':False,'challengeSolved':False,
        'warning':'Partial Explorer ZEC-origin scope excludes masking routes. Quotes are not executed swaps. '
                  'Exact receiver reuse is metadata linkage, not wallet ownership or a note/nullifier link. '
                  'Diversified addresses and opaque/uncollected notes prevent wallet exclusions.'}
    if nonpending:
        from check_challenge7_explorer_positive_control import expected_route,analyze_rows
        controls=[o['metadata'] for o in executed if o['isTargetSelf']]
        control=analyze_rows(controls,target['quoteTimestamp'],expected_route(repo))
        analysis['knownTargetRouteBindings']=control['exactDepositRows']
        analysis['knownTargetRouteExactlyBound']=len(control['exactDepositRows'])==1 and all(
            r['exactKnownRouteFields'] for r in control['exactDepositRows'])
        analysis['exhaustedCoverageIntervals']=exhausted_intervals(coverage)
        analysis['isLiveCheckpointSnapshot']=cm.get('snapshot',False)
    write_rows(out/'source-inventory.jsonl',inventory);write_rows(out/'decoded-addresses.jsonl',decoded)
    write_rows(out/'target-receiver-matches.jsonl',target_matches);write_rows(out/'note-receiver-matches.jsonl',note_matches)
    write_rows(out/'executed-or-origin-reported-quotes.jsonl',executed)
    write_rows(out/'target-destination-quotes.jsonl',target_dest);write_rows(out/'invalid-addresses.jsonl',invalid)
    dump(out/'analysis.json',analysis)
    for s in inventory:
        if digest(Path(s['path']))!=s['sha256']:raise ValueError('source changed during audit')
    if sorted((src/'http-responses').glob('*.json'))!=paths or any(digest(src/n)!=h for n,h in source_pins.items()):
        raise ValueError('source set/checkpoint changed during audit')
    artifacts=('source-inventory.jsonl','decoded-addresses.jsonl','target-receiver-matches.jsonl',
       'note-receiver-matches.jsonl','executed-or-origin-reported-quotes.jsonl',
       'target-destination-quotes.jsonl','invalid-addresses.jsonl','analysis.json')
    dump(out/'manifest.json',{'offlineAuditComplete':True,'newHttpCalls':0,'challengeSolved':False,
        'scriptSha256':digest(Path(__file__)),'baselineSha256':digest(baseline),
        'sourceCheckpointSha256':digest(src/'checkpoint.json'),'sourceManifestSha256':digest(src/'manifest.json'),
        'artifactHashes':{n:digest(out/n) for n in artifacts}})
    print(json.dumps({k:analysis[k] for k in ('sourcePages','rowOccurrences','uniqueUnifiedStrings',
        'targetReceiverMatchOccurrences','nonTargetReceiverMatchOccurrences',
        'noteReceiverMatchOccurrences','distinctMatchedBaselineNotes','collectorStopped')},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nonpending',action='store_true',help='Analyze the separate corrected-cutoff nonpending scope.')
    parser.add_argument('--snapshot',action='store_true',help='Read-only stable snapshot of a live nonpending collector; never stops it.')
    parser.add_argument('--baseline-v5',action='store_true',help='Compare against the separately verified 47-note supplement; keep V4 outputs unchanged.')
    args=parser.parse_args()
    if args.snapshot and not args.nonpending:parser.error('--snapshot requires --nonpending')
    if args.baseline_v5 and not args.nonpending:parser.error('--baseline-v5 requires --nonpending')
    source=None
    output=Path(__file__).resolve().parents[1]/('challenge7-outgoing-nonpending-analysis'
                                               if args.nonpending else 'challenge7-outgoing-collection-analysis')
    if args.snapshot:
        repo=Path(__file__).resolve().parents[1]
        source,output=live_snapshot(repo,repo/'challenge7-outgoing-nonpending-collection')
    if args.baseline_v5:output=output.with_name(output.name+'-v5')
    if output.is_symlink():raise ValueError('output symlink not allowed')
    dump(output/'manifest.json',{'offlineAuditComplete':False,'stopped':'audit in progress','newHttpCalls':0})
    try:main(args.nonpending,source,output,args.baseline_v5)
    except Exception as exc:
        dump(output/'manifest.json',{'offlineAuditComplete':False,'stopped':str(exc),'newHttpCalls':0})
        raise
