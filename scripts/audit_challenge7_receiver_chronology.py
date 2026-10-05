#!/usr/bin/env python3
"""Separate prior-note receiver reuse from notes returned after outgoing quotes.

Offline by default. --fetch enables only up to --max-http-calls public 1Click
status GETs for declared refund controls. No JWT, wallet identities, signatures,
transaction submission, note-spend inference, or changes to frozen inputs.
"""
import argparse
import hashlib
import json
import urllib.parse
from collections import Counter
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows, ANCHOR, TARGET
from analyze_challenge7_outgoing_collection import page_source, KEEP
from check_challenge7_quote_receiver_reuse import typed_receivers
from check_challenge7_refund_receiver import BASELINE_SHA
from collect_challenge7_outgoing_quotes import stamp
from trace_challenge7_free_near import digest
from trace_challenge7_user_origins import Reader

MATCH_SHA='69ce6872d6723e4e7dc8057ccec606a6209bafa05604086612f01e29a3d97a72'
DECODE_SHA='3a2b23883c0ee44b7e7ea878b6f6fa6f38292651a4db9b24903ff191742e02aa'
ANALYSIS_SHA='d0ecf641af7c491a62e8e808d2b3df3bdb3a637bef60cb156628916936500147'


def local(repo,path):
    path=Path(path)
    if path.is_symlink() or repo not in path.resolve().parents:
        raise ValueError('evidence path must stay inside the hunt repository')
    return path


def pinned_rows(path,expected):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('frozen input SHA mismatch: '+str(path))
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def hashes(values):
    if not isinstance(values,list):raise ValueError('transaction hashes must be a list')
    result=set()
    for value in values:
        h=value.get('hash') if isinstance(value,dict) else value
        if not isinstance(h,str):raise ValueError('malformed transaction hash')
        result.add(h)
    return result


def classify(note,match):
    metadata=match['metadata']
    prior=stamp(note['blockTime'])<stamp(metadata['createdAt'])
    origin=note['txid'] in hashes(metadata.get('originChainTxHashes') or [])
    destination=note['txid'] in hashes(metadata.get('destinationChainTxHashes') or [])
    relation=('origin-and-destination-list' if origin and destination else
              'origin-list' if origin else 'destination-list' if destination else 'neither-list')
    # These are hash-list roles, not inferred funding/refund roles. Refunds can
    # be included in either list; the original 1Click status is checked below.
    return {'noteId':note['id'],'noteTxid':note['txid'],'noteValueZat':note['valueZat'],
        'notePool':note['pool'],'noteHeight':note['blockHeight'],'noteBlockTime':note['blockTime'],
        'field':match['field'],'receiverKind':match['receiverKind'],'receiverRaw':match['receiverRaw'],
        'quoteCreatedAt':metadata['createdAt'],'quoteDeposit':metadata['depositAddress'],
        'quoteMemo':metadata.get('depositMemo'),'quoteStatus':metadata['status'],
        'quoteDestinationAsset':metadata['destinationAsset'],'hashListRelation':relation,
        'createdBeforeQuote':prior,'chronologyClass':'before-quote' if prior else 'at-or-after-quote',
        'enoughForTargetWithoutAnotherNote':note['valueZat']>=TARGET,
        'isTargetSelf':match['isTargetSelf'],'source':match['source'],
        'sourceSha256':match['sourceSha256'],'rowIndex':match['rowIndex'],
        'rowCanonicalSha256':match['rowCanonicalSha256'],
        'metadataReceiverLinkOnly':True,'noteConsumptionProven':False,'ownershipProven':False,
        'warning':'Quote creation is not spend time. Later notes may still precede funding; '
                  'origin/destination lists alone do not identify a deposit or refund.'}


def bind_status(value,match,note):
    metadata=match['metadata']; qr=value.get('quoteResponse') or {}
    request=qr.get('quoteRequest') or {}; quote=qr.get('quote') or {}; details=value.get('swapDetails') or {}
    amount_sources={}
    for field in ('amountIn','amountOut'):
        if details.get(field) is not None:
            expected=details[field];amount_sources[field]='actual-swap-details'
        elif value.get('status')=='REFUNDED':
            expected=quote.get(field);amount_sources[field]='quoted-not-executed'
        else:
            raise ValueError('successful status lacks actual swap amount')
        if str(expected)!=str(metadata.get(field)):
            raise ValueError('public status/Explorer amount disagreement: '+field)
    if (quote.get('depositAddress')!=metadata['depositAddress']
            or quote.get('depositMemo')!=metadata.get('depositMemo')
            or any(request.get(k)!=metadata.get(k) for k in ('originAsset','destinationAsset','refundTo','recipient'))
            or value.get('status')!=metadata['status']
            or hashes(details.get('originChainTxHashes') or [])!=hashes(metadata.get('originChainTxHashes') or [])
            or hashes(details.get('destinationChainTxHashes') or [])!=hashes(metadata.get('destinationChainTxHashes') or [])):
        raise ValueError('public status and saved Explorer quote disagree')
    returned=details.get('refundedAmount')
    returned=int(returned) if isinstance(returned,str) and returned.isdigit() else None
    exact=(match['field']=='refundTo' and request.get('refundType')=='ORIGIN_CHAIN'
           and returned==note['valueZat'] and note['txid'] in
           (hashes(details.get('originChainTxHashes') or [])|hashes(details.get('destinationChainTxHashes') or [])))
    return {'statusRouteBound':True,'quoteTimestamp':qr.get('timestamp'),
        'depositedAmount':details.get('depositedAmount'),'actualSwappedAmount':details.get('amountIn'),
        'refundedAmount':details.get('refundedAmount'),'refundReason':details.get('refundReason'),
        'reportedRefundFee':details.get('refundFee'),
        'actualNoteMinusReportedRefundZat':note['valueZat']-returned if returned is not None else None,
        'grossUnswappedMinusActualNoteZat':int(details['depositedAmount'])-
            int(details.get('amountIn') or 0)-note['valueZat'],
        'refundType':request.get('refundType'),'exactReturnedNoteValueAndReceiver':exact,
        'explorerAmountBindings':amount_sources,
        'noteConsumptionProven':False,'targetPrivateSpendLink':False,
        'warning':'Amount/receiver/hash-list binding supports a returned-note classification; '
                  'not proof of which private inputs funded this or the target swap.'}


def audit(args):
    repo=Path(__file__).resolve().parents[1]
    src=repo/'challenge7-outgoing-collection-analysis'
    out=local(repo,repo/'challenge7-receiver-chronology-data');out.mkdir(exist_ok=True)
    source_paths={};baseline=repo/'challenge7-decoded-baseline-v4-data/decoded-notes.jsonl'
    notes_list=pinned_rows(baseline,BASELINE_SHA);notes={n['id']:n for n in notes_list}
    if len(notes)!=len(notes_list):raise ValueError('duplicate note identity')
    matches=pinned_rows(src/'note-receiver-matches.jsonl',MATCH_SHA)
    decoded=pinned_rows(src/'decoded-addresses.jsonl',DECODE_SHA)
    if digest(src/'analysis.json')!=ANALYSIS_SHA:raise ValueError('frozen comparison analysis changed')
    manifest=json.loads((src/'manifest.json').read_text())
    if (not manifest.get('offlineAuditComplete') or manifest['artifactHashes']['analysis.json']!=ANALYSIS_SHA
            or manifest['artifactHashes']['note-receiver-matches.jsonl']!=MATCH_SHA):
        raise ValueError('comparison manifest incomplete or inconsistent')
    by_address={d['address']:typed_receivers(d['decode']) for d in decoded}
    source_paths.update({str(baseline):BASELINE_SHA,str(src/'note-receiver-matches.jsonl'):MATCH_SHA,
                         str(src/'decoded-addresses.jsonl'):DECODE_SHA,str(src/'analysis.json'):ANALYSIS_SHA,
                         str(src/'manifest.json'):digest(src/'manifest.json')})
    pages={};edges=[];controls=[];control_keys=set()
    for match in matches:
        path=local(repo,match['source']);key=str(path)
        if key not in pages:
            if digest(path)!=match['sourceSha256']:raise ValueError('original Explorer page changed')
            pages[key]=page_source(path)[0];source_paths[key]=match['sourceSha256']
        row=pages[key][match['rowIndex']]
        rh=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if (rh!=match['rowCanonicalSha256'] or {k:row.get(k) for k in KEEP}!=match['metadata']
                or row.get(match['field'])!=match['address']
                or by_address[match['address']].get(match['receiverKind'])!=match['receiverRaw']):
            raise ValueError('match not bound to its original quote/typed receiver')
        for ident in match['matchedBaselineNoteIds']:
            note=notes[ident];kind='orchard' if note['pool'] in ('ironwood','orchard') else 'sapling'
            if (note['blockHeight']>ANCHOR or note['valueZat']<=0 or kind!=match['receiverKind']
                    or match['receiverRaw'] not in note['receiverBytes']):
                raise ValueError('note/receiver/anchor disagreement')
            edge=classify(note,match);edges.append(edge)
            identity=(edge['quoteDeposit'],edge['quoteMemo'])
            if (edge['field']=='refundTo' and edge['quoteStatus'] in ('SUCCESS','REFUNDED')
                    and not edge['createdBeforeQuote'] and edge['hashListRelation']!='neither-list'
                    and identity not in control_keys):
                controls.append((edge,match,note));control_keys.add(identity)
    # Prefer closest returned values for an explicitly bounded control. This
    # is a diagnostic sample, not a source ranking or significance test.
    controls.sort(key=lambda e:(abs(e[0]['noteValueZat']-TARGET),e[0]['noteId']))
    reader=Reader(out,args.fetch,args.max_http_calls,1.1);checked=[];stopped=None
    for edge,match,note in controls[:args.controls]:
        params={'depositAddress':edge['quoteDeposit']}
        if edge['quoteMemo'] is not None:params['depositMemo']=edge['quoteMemo']
        url='https://1click.chaindefuser.com/v0/status?'+urllib.parse.urlencode(params)
        try:
            value=reader.request(url)
            checked.append({**edge,'publicStatus':bind_status(value,match,note),
                            'publicStatusSource':reader.index[-1]})
        except Exception as exc:
            stopped=str(exc);break  # Never retry/rotate on network/auth/rate failures.
    prior=[e for e in edges if e['createdBeforeQuote'] and e['field']=='refundTo'
           and e['quoteStatus']=='SUCCESS' and not e['isTargetSelf']]
    output={'offlineComparisonComplete':True,'newHttpCalls':reader.calls,'challengeSolved':False,
        'targetPrivateSpendLink':False,'matchOccurrences':len(matches),'noteQuoteEdges':len(edges),
        'edgeClassCounts':dict(Counter('|'.join((e['field'],e['quoteStatus'],e['hashListRelation'],e['chronologyClass'])) for e in edges)),
        'successPriorRefundEdges':len(prior),'successPriorRefundNotes':len({e['noteId'] for e in prior}),
        'successPriorRefundQuotes':len({(e['quoteDeposit'],e['quoteMemo']) for e in prior}),
        'successPriorRefundSufficientSingles':len({e['noteId'] for e in prior if e['enoughForTargetWithoutAnotherNote']}),
        'atOrAfterQuoteListedEdges':sum(not e['createdBeforeQuote'] and e['hashListRelation']!='neither-list' for e in edges),
        'refundControlsSelected':min(len(controls),args.controls),'refundControlsChecked':len(checked),
        'exactReturnedNoteControls':sum(c['publicStatus']['exactReturnedNoteValueAndReceiver'] for c in checked),
        'controlFetchStopped':stopped,'historicalOutgoingCoverageComplete':False,
        'warning':'This is a role/chronology audit of an incomplete recent outgoing scope. '
                  'Neither quote-time ordering nor receiver reuse establishes note availability/consumption. '
                  'Private change/consolidation, later-funded quotes and unrecovered notes remain possible.'}
    write_rows(out/'note-quote-edges.jsonl',edges);write_rows(out/'prior-success-refund-links.jsonl',prior)
    write_rows(out/'public-refund-controls.jsonl',checked);dump(out/'analysis.json',output)
    for path,sha in source_paths.items():
        if digest(local(repo,path))!=sha:raise ValueError('source changed during audit')
    for response in reader.index:
        if digest(local(repo,response['path']))!=response['sha256']:raise ValueError('status source changed during audit')
    dump(out/'manifest.json',{'offlineComparisonComplete':True,'newHttpCalls':reader.calls,
        'challengeSolved':False,'targetPrivateSpendLink':False,'controlFetchStopped':stopped,
        'scriptSha256':digest(Path(__file__)),'frozenInputHashes':source_paths,'publicResponsesUsed':reader.index,
        'artifactHashes':{n:digest(out/n) for n in ('analysis.json','note-quote-edges.jsonl',
                                                'prior-success-refund-links.jsonl','public-refund-controls.jsonl')}})
    print(json.dumps({k:v for k,v in output.items() if k!='edgeClassCounts'},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch',action='store_true')
    parser.add_argument('--max-http-calls',type=int,default=8)
    parser.add_argument('--controls',type=int,default=8)
    args=parser.parse_args()
    if args.controls<0 or args.max_http_calls<0:parser.error('limits must be nonnegative')
    audit(args)
