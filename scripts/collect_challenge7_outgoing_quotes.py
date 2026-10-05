#!/usr/bin/env python3
"""Paced, resumable Explorer reads for the missing historical ZEC-origin scope.

--fetch explicitly enables network reads. JWT comes only from the environment,
never command arguments or saved evidence. No amount/referral/destination filter.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump
from check_challenge7_outgoing_quote_cache import ZEC_ASSETS

API = 'https://explorer.near-intents.org/api/v0/transactions'
ALL_STATUSES = 'FAILED,INCOMPLETE_DEPOSIT,PENDING_DEPOSIT,PROCESSING,REFUNDED,SUCCESS'
OVERLAP = timedelta(milliseconds=1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward a partner credential to any redirected destination.
        return None


def stamp(value):
    result = datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.tzinfo is None:
        raise ValueError('explicit timezone required')
    return result.astimezone(timezone.utc)


def iso(value):
    return value.isoformat(timespec='microseconds').replace('+00:00','Z')


def query(state):
    params = {'numberOfTransactions':'1000','direction':'next','fromChainId':'zec',
              'statuses':state.get('scope',{}).get('statuses',ALL_STATUSES),'startTimestamp':state['windowStart'],
              'endTimestamp':state['windowEnd']}
    if state.get('lastDepositAddress'):
        params['lastDepositAddress'] = state['lastDepositAddress']
        if state.get('lastDepositMemo') is not None:
            params['lastDepositMemo'] = str(state['lastDepositMemo'])
    return API+'?'+urllib.parse.urlencode(params)


def validate_page(rows, state):
    if not isinstance(rows,list) or len(rows)>1000:
        raise ValueError('expected at most 1000 API transaction objects')
    clocks = []
    for row in rows:
        if (not isinstance(row,dict) or row.get('originAsset') not in ZEC_ASSETS
                or not isinstance(row.get('destinationAsset'),str)
                or not isinstance(row.get('depositAddress'),str) or not row['depositAddress']
                or row.get('status') not in state.get('scope',{}).get('statuses',ALL_STATUSES).split(',')):
            raise ValueError('response violates requested ZEC-origin scope')
        clock = stamp(row['createdAt'])
        if not stamp(state['windowStart'])<clock<stamp(state['windowEnd']):
            raise ValueError('transaction outside exclusive requested time window')
        clocks.append(clock)
    if clocks != sorted(clocks,reverse=True):
        raise ValueError('API page is not newest-to-oldest')
    if len(rows)==1000:
        last = rows[-1]
        cursor = (last['depositAddress'],last.get('depositMemo'))
        if cursor == (state.get('lastDepositAddress'),state.get('lastDepositMemo')):
            raise ValueError('pagination cursor failed to advance')
    return rows


def advance(state, rows, floor, window_days):
    state = dict(state)
    if len(rows)==1000:
        state['lastDepositAddress'] = rows[-1]['depositAddress']
        state['lastDepositMemo'] = rows[-1].get('depositMemo')
    else:
        start = stamp(state['windowStart'])
        if start<=floor:
            state['complete'] = True
        else:
            end = start+OVERLAP  # Include the previously excluded exact boundary.
            state.update(windowEnd=iso(end),windowStart=iso(max(floor,end-timedelta(days=window_days))),
                         lastDepositAddress=None,lastDepositMemo=None)
    return state


def shrink(state, reason='5xx'):
    """Bisect a failed interval; subsequent windows retain the smaller width.

    Only the older start moves. Once the newer half is exhausted, advance()
    walks backwards into the omitted half, so no historical interval is skipped.
    Already-saved parent pages remain evidence, not independent transactions.
    """
    state = dict(state)
    start,end = stamp(state['windowStart']),stamp(state['windowEnd'])
    if end-start<=timedelta(hours=1):
        raise ValueError(reason+' at <=1-hour window; checkpointed, no blind retries')
    state.update(windowStart=iso(start+(end-start)/2),lastDepositAddress=None,lastDepositMemo=None)
    state['adaptiveWindowDays'] = (end-start).total_seconds()/2/86400
    return state


def is_timeout(exc):
    """Only transport timeouts qualify for recovery, not auth/DNS/rate errors."""
    return (isinstance(exc,(TimeoutError,socket.timeout))
            or isinstance(exc,urllib.error.URLError)
            and isinstance(exc.reason,(TimeoutError,socket.timeout)))


def collect(args):
    repo = Path(__file__).resolve().parents[1]
    folder=getattr(args,'output_dir','challenge7-outgoing-quote-collection')
    if Path(folder).name!=folder or not folder.startswith('challenge7-'):
        raise ValueError('use a single challenge7-* output directory name inside the repository')
    out = repo/folder
    if out.is_symlink() or repo not in out.resolve().parents:
        raise ValueError('collector output must remain inside repository')
    out.mkdir(parents=True,exist_ok=True)
    statuses=getattr(args,'statuses',ALL_STATUSES)
    requested=statuses.split(',')
    if not requested or len(set(requested))!=len(requested) or not set(requested)<=set(ALL_STATUSES.split(',')):
        raise ValueError('invalid/duplicated requested statuses')
    since,until = stamp(args.since),stamp(args.until)
    if since>=until or args.window_days<=0 or args.max_http_calls<1:
        raise ValueError('invalid date range/window/request cap')
    scope = {'since':iso(since),'until':iso(until),'fromChainId':'zec','statuses':statuses,
             'windowDays':args.window_days,'pageSize':1000,'amountFilter':None,
             'destinationFilter':None,'referralFilter':None}
    checkpoint = out/'checkpoint.json'
    floor,end = since-OVERLAP,until+OVERLAP
    state = {'scope':scope,'windowStart':iso(max(floor,end-timedelta(days=args.window_days))),
             'windowEnd':iso(end),'lastDepositAddress':None,'lastDepositMemo':None,
             'complete':False,'successfulPages':0,'rowOccurrences':0,'serverErrorWindows':0}
    if checkpoint.exists():
        state = json.loads(checkpoint.read_text())
        if state['scope']!=scope:
            raise ValueError('existing checkpoint uses a different scope; do not overwrite')
    if not args.fetch:
        print(json.dumps({'networkEnabled':False,'scope':scope,'checkpoint':state,
                          'instruction':'Set NEAR_INTENTS_JWT locally, then add --fetch.'},indent=2))
        return
    if state['complete']:
        print('already complete; no requests made')
        return
    jwt = os.environ.get('NEAR_INTENTS_JWT','').strip()
    if not jwt:
        raise ValueError('NEAR_INTENTS_JWT is missing; set it locally, never paste into chat')
    lock = out/'collector.lock'
    handle = os.open(str(lock),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(handle)
    calls,stopped = 0,None
    timeout=getattr(args,'timeout',30)
    if timeout<=0 or timeout>120:
        lock.unlink()
        raise ValueError('timeout must be greater than zero and at most 120 seconds')
    opener = urllib.request.build_opener(NoRedirect())
    try:
        while not state['complete'] and calls<args.max_http_calls:
            url = query(state)
            cache = out/'http-responses'/(hashlib.sha256(url.encode()).hexdigest()+'.json')
            if cache.exists():
                envelope = json.loads(cache.read_text())
                raw = envelope['rawUtf8'].encode()
                if (envelope['url']!=url or envelope['request'] is not None
                        or envelope['httpStatus']!=200
                        or hashlib.sha256(raw).hexdigest()!=envelope['responseBytesSha256']
                        or json.loads(raw)!=envelope['response']):
                    raise ValueError('cached API response integrity mismatch')
                rows = envelope['response']
            else:
                # Fixed minimum spacing across process restarts as well.
                time.sleep(5.5)
                request = urllib.request.Request(url,headers={'Authorization':'Bearer '+jwt,
                                                              'accept':'application/json'})
                calls += 1
                print('request='+str(calls)+' saved_pages='+str(state['successfulPages'])+
                      ' window='+state['windowStart']+'..'+state['windowEnd']+
                      ' cursor='+str(bool(state.get('lastDepositAddress')))+
                      ' timeout_seconds='+str(timeout),flush=True)
                try:
                    with opener.open(request,timeout=timeout) as response:
                        raw = response.read()
                except urllib.error.HTTPError as exc:
                    if exc.code>=500:
                        state = shrink(state)
                        state['serverErrorWindows'] += 1
                        dump(checkpoint,state)
                        print('HTTP '+str(exc.code)+'; narrowed window, saved checkpoint',flush=True)
                        continue
                    # Never print headers, credentials, error body, or retry 429.
                    raise ValueError('HTTP '+str(exc.code)+'; stopped without retry') from None
                except Exception as exc:
                    if not is_timeout(exc):
                        raise
                    state=shrink(state,'transport timeout')
                    state['timeoutWindows']=state.get('timeoutWindows',0)+1
                    dump(checkpoint,state)
                    print('transport timeout; narrowed window and saved checkpoint; '
                          'no retry of the unchanged request',flush=True)
                    continue
                rows = json.loads(raw)
                validate_page(rows,state)
                dump(cache,{'url':url,'request':None,'httpStatus':200,
                    'fetchedAt':datetime.now(timezone.utc).isoformat(),
                    'responseBytesSha256':hashlib.sha256(raw).hexdigest(),
                    'rawUtf8':raw.decode(),'response':rows})
            validate_page(rows,state)
            state['successfulPages'] += 1
            state['rowOccurrences'] += len(rows)  # Duplicates/overlap not unique swaps.
            state = advance(state,rows,floor,state.get('adaptiveWindowDays',args.window_days))
            dump(checkpoint,state)
            print('pages='+str(state['successfulPages'])+' rows='+str(state['rowOccurrences'])+
                  ' HTTP_this_run='+str(calls)+' complete='+str(state['complete'])+
                  ' next_window='+state['windowStart']+'..'+state['windowEnd'],flush=True)
        if not state['complete']:
            stopped = 'per-run HTTP cap reached; rerun same command to resume'
    except KeyboardInterrupt:
        stopped = 'interrupted; checkpoint preserved'
    except Exception as exc:
        stopped = str(exc)
    finally:
        dump(checkpoint,state)
        dump(out/'manifest.json',{'scope':scope,'retrievalComplete':state['complete'],
            'newHttpCallsThisRun':calls,'stopped':stopped,'successfulPages':state['successfulPages'],
            'rowOccurrences':state['rowOccurrences'],'challengeSolved':False,
            'transportPolicy':{'timeoutSeconds':timeout,'minimumSpacingSeconds':5.5,
                'timeoutWindowBisection':True,'minimumFailedWindowHours':1,
                'timeoutWindows':state.get('timeoutWindows',0)},
            'warning':'Explorer chain filters exclude masking transactions; this is not all private activity.'})
        lock.unlink()  # Only this invocation's transient coordination file.
    print('done: retrievalComplete='+str(state['complete'])+' stopped='+str(stopped),flush=True)
    if stopped:
        raise SystemExit(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch',action='store_true')
    parser.add_argument('--since',default='2025-08-21T00:00:00Z')
    parser.add_argument('--until',default='2026-09-19T10:00:02.472Z')
    parser.add_argument('--window-days',type=float,default=7)
    parser.add_argument('--max-http-calls',type=int,default=300)
    parser.add_argument('--timeout',type=float,default=30,
                        help='Per-read timeout (max 120s); timeouts halve the interval down to 1 hour.')
    parser.add_argument('--output-dir',default='challenge7-outgoing-quote-collection',
                        help='A single challenge7-* folder name; new scopes must use separate output.')
    parser.add_argument('--statuses',default=ALL_STATUSES,
                        help='Comma-separated statuses; excluding pending quotes changes coverage, not just speed.')
    collect(parser.parse_args())


if __name__=='__main__': main()
