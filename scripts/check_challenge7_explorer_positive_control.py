#!/usr/bin/env python3
"""Tiny read-only known-route diagnostic; cache-only unless --fetch.

--authenticated reads NEAR_INTENTS_JWT locally, never prints/saves the token.
Four paced exact-search requests, no broad history scrape or automatic retries.
"""
import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

from analyze_challenge7_baseline import dump
from collect_challenge7_outgoing_quotes import API, ALL_STATUSES, NoRedirect, stamp, iso
from check_challenge7_refund_receiver import DEPOSIT, TARGET_TX, DESTINATION
from check_challenge7_quote_receiver_reuse import target_evidence
from trace_challenge7_free_near import digest


def queries(quote_timestamp):
    common={'numberOfTransactions':'1000','statuses':ALL_STATUSES,'direction':'next'}
    original_end=iso(stamp(quote_timestamp)+timedelta(milliseconds=1))
    return [('deposit-unfiltered',{**common,'search':DEPOSIT}),
            ('deposit-zec-filter',{**common,'search':DEPOSIT,'fromChainId':'zec'}),
            ('deposit-original-end',{**common,'search':DEPOSIT,'fromChainId':'zec',
                                     'endTimestamp':original_end}),
            ('origin-tx-unfiltered',{**common,'search':TARGET_TX})]


def hashes(values):
    return {v.get('hash') if isinstance(v,dict) else v for v in values or []}


def expected_route(repo):
    # Caller validates the pinned target envelope with target_evidence first.
    m=json.loads((repo/'challenge7-refund-receiver-data/manifest.json').read_text())
    v=json.loads(Path(m['responsesUsed'][0]['path']).read_text())['response']
    return {'swappedAmountIn':v['swapDetails']['amountIn'],
            'depositedAmount':v['swapDetails']['depositedAmount'],
            'quoteAmountIn':v['quoteResponse']['quote']['amountIn'],
            'amountOut':v['swapDetails']['amountOut'],
            'refundTo':v['quoteResponse']['quoteRequest']['refundTo'],
            'destinationHashes':sorted(hashes(v['swapDetails']['destinationChainTxHashes'])),
            'nearHashes':sorted(v['swapDetails']['nearTxHashes'])}


def analyze_rows(rows,quote_timestamp,expected=None):
    if not isinstance(rows,list) or len(rows)>1000 or any(not isinstance(r,dict) for r in rows):
        raise ValueError('unexpected Explorer array schema')
    result=[]
    for row in rows:
        if row.get('depositAddress')!=DEPOSIT:continue
        clocks=stamp(row['createdAt']);end=stamp(quote_timestamp)+timedelta(milliseconds=1)
        exact=(row.get('status')=='SUCCESS' and row.get('originAsset')=='nep141:zec.omft.near'
               and row.get('destinationAsset')=='nep141:eth.omft.near'
               and str(row.get('recipient','')).lower()==DESTINATION.lower()
               and str(row.get('amountIn'))==(expected['swappedAmountIn'] if expected else '3862724')
               and str(row.get('amountOut'))=='22712389229785027'
               and TARGET_TX in hashes(row.get('originChainTxHashes')))
        if expected:
            exact=exact and (row.get('refundTo')==expected['refundTo']
                  and sorted(hashes(row.get('destinationChainTxHashes')))==expected['destinationHashes']
                  and sorted(row.get('nearTxHashes') or [])==expected['nearHashes'])
        result.append({'createdAt':row['createdAt'],'quoteTimestamp':quote_timestamp,
                       'createdAtDeltaSeconds':(clocks-stamp(quote_timestamp)).total_seconds(),
                       'insideOriginalEndTimestamp':clocks<end,'exactKnownRouteFields':exact,
                       'metadata':row,'targetPrivateSpendLink':False,'ownershipProven':False})
    return {'rowsReturned':len(rows),'pageMayBeTruncated':len(rows)==1000,'exactDepositRows':result}


def diagnose(fetch=False,authenticated=False):
    repo=Path(__file__).resolve().parents[1];out=repo/'challenge7-explorer-positive-control-data'
    if out.is_symlink():raise ValueError('output symlink not allowed')
    out.mkdir(parents=True,exist_ok=True)
    target=target_evidence(repo,repo/'decoder/target/release/unified_receivers')
    expected=expected_route(repo)
    token=os.environ.get('NEAR_INTENTS_JWT','').strip() if authenticated and fetch else None
    if authenticated and fetch and not token:raise ValueError('NEAR_INTENTS_JWT missing; set locally, not in chat')
    results={};sources=[];failures=[];calls=0;stopped=None
    opener=urllib.request.build_opener(NoRedirect())
    for name,params in queries(target['quoteTimestamp']):
        url=API+'?'+urllib.parse.urlencode(params)
        path=out/'http-responses'/(hashlib.sha256(url.encode()).hexdigest()+'.json')
        if path.exists():
            e=json.loads(path.read_text());raw=e['rawUtf8'].encode()
            if (e['url']!=url or e['request'] is not None or e['httpStatus']!=200
                    or hashlib.sha256(raw).hexdigest()!=e['responseBytesSha256']
                    or json.loads(raw)!=e['response']):raise ValueError('cached original-response integrity mismatch')
        elif not fetch:
            stopped='missing cached exact-search response; --fetch required';break
        else:
            time.sleep(5.5);calls+=1
            headers={'accept':'application/json'}
            if token:headers['Authorization']='Bearer '+token
            request=urllib.request.Request(url,headers=headers)
            try:
                with opener.open(request,timeout=30) as r:raw=r.read();status=r.status
                e={'url':url,'request':None,'httpStatus':status,
                   'fetchedAt':datetime.now(timezone.utc).isoformat(),'rawUtf8':raw.decode(),
                   'responseBytesSha256':hashlib.sha256(raw).hexdigest(),'response':json.loads(raw)}
                analyze_rows(e['response'],target['quoteTimestamp'],expected)
                dump(path,e)
            except urllib.error.HTTPError as exc:
                stopped='HTTP '+str(exc.code)+'; stopped without retry'
                failures.append({'url':url,'httpStatus':exc.code,'authenticated':authenticated,
                                 'errorBodySaved':False,'headersSaved':False});break
            except (OSError,ValueError) as exc:
                # No HTTP request headers/token or server error body in evidence.
                stopped=type(exc).__name__+' while reading/validating response; stopped without retry';break
        results[name]=analyze_rows(e['response'],target['quoteTimestamp'],expected)
        sources.append({'name':name,'path':str(path.resolve()),'sha256':digest(path),'url':url})
        print(name+': returned='+str(results[name]['rowsReturned'])+
              ' exact_deposit='+str(len(results[name]['exactDepositRows'])),flush=True)
    baseline=out/'public-probe.json'
    if fetch and not authenticated:
        dump(baseline,{'newHttpCalls':calls,'failures':failures,'stopped':stopped})
    # Preserve the user's original derived results (including the original
    # gross-vs-swapped checker bug) before an offline corrected replay.
    for filename in ('analysis.json','manifest.json'):
        existing=out/filename
        if existing.exists():
            archive=out/'previous-runs'/(digest(existing)+'-'+filename)
            if not archive.exists():dump(archive,json.loads(existing.read_text()))
    analysis={'queries':results,'target':target,'expectedRoute':expected,'stopped':stopped,'newHttpCalls':calls,
              'allFourQueriesComplete':len(results)==4,'challengeSolved':False,
              'targetPrivateSpendLink':False,'failures':failures}
    dump(out/'analysis.json',analysis)
    dump(out/'manifest.json',{'scriptSha256':digest(Path(__file__)),'analysisSha256':digest(out/'analysis.json'),
          'responsesUsed':sources,'newHttpCalls':calls,'stopped':stopped,'challengeSolved':False})
    print(json.dumps({'completedQueries':len(results),'newHttpCalls':calls,'stopped':stopped},indent=2))
    return 2 if stopped else 0


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fetch',action='store_true')
    p.add_argument('--authenticated',action='store_true',help='Read locally exported JWT only with --fetch.')
    a=p.parse_args();raise SystemExit(diagnose(a.fetch,a.authenticated))


if __name__=='__main__':main()
