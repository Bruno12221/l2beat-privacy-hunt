#!/usr/bin/env python3
"""Repository-local, bounded public candidate/author-seed history comparison.

Cache-only unless --fetch. No authentication, identities behind unrelated
wallets, ownership clustering from exchange/router contacts, or PR operations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from trace_challenge7_user_origins import Reader
from trace_challenge7_free_near import CheckpointStop, digest

CANDIDATE='0xd9e5df6acc9815121d3e99b49f26e712eb4fe41d'
SEEDS={
    '0x09fbb3e9114e6b5a938f591c8bf75203d8075507':'author-disclosed wallet',
    '0x391098f86054757535910242841ff6dcbb942c77':'historical ENS custody recipient',
    '0x0a40c462d49803517cafe9830f83431cea4b64e9':'historical ENS custody predecessor',
    '0xf9df529961bf8d10fa026ce7a931648bf89b3593':'historical ENS transfer counterparty',
    '0xcfe5fbec9b35f04a32414e1a09f835123f69ecf6':'historical indirect operational lead',
    '0x8d5a4fe39f7c4407431e48bd6bf727e5a159f98a':'public challenge destination',
}
HOSTS={'Ethereum':'https://eth.blockscout.com','Base':'https://base.blockscout.com'}
ENS_CONTRACTS={'0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85':'ENS Base Registrar',
               '0xd4416b13d2b3a9abae7acd5d6c2bbdbe25686401':'ENS NameWrapper'}
CUTOFF='2026-09-19T10:01:11'


def temporal(row):
    value=row.get('timestamp')
    if not isinstance(value,str): return 'unknown'
    # Blockscout supplies UTC ISO timestamps. Fail rather than assume timezone.
    if not value.endswith('Z'): raise ValueError('non-UTC indexer timestamp')
    return 'pre-target' if value[:19]<=CUTOFF else 'post-target'


def sides(row):
    return {k:str((row.get(k) or {}).get('hash') or '').lower() for k in ('from','to')}


def item_id(row,kind):
    if kind=='transactions': return row['hash'].lower()
    if kind=='token-transfers':
        return json.dumps((row['transaction_hash'].lower(),row['log_index'],
                    (row.get('token') or {}).get('address_hash'),row.get('total')),sort_keys=True)
    return json.dumps((row.get('transaction_hash'),row.get('index'),row.get('block_number'),
                sides(row),row.get('value'),row.get('type')),sort_keys=True)


def validate_page(value,address,kind,previous_order=None):
    if not isinstance(value,dict) or not isinstance(value.get('items'),list):
        raise ValueError('unexpected Blockscout page schema')
    items=value['items']; clocks=[]
    for row in items:
        if not isinstance(row,dict) or address not in sides(row).values():
            raise ValueError('returned row does not involve exact queried address')
        temporal(row)
        if row.get('timestamp'): clocks.append(row['timestamp'])
        item_id(row,kind)
    if clocks!=sorted(clocks,reverse=True): raise ValueError('page time order disagrees')
    if previous_order and clocks and clocks[0]>previous_order:
        raise ValueError('pagination moved forward in time')
    cursor=value.get('next_page_params')
    if cursor is not None and (not isinstance(cursor,dict) or not cursor or not items):
        raise ValueError('invalid/nonadvancing cursor')
    return items,cursor,clocks[-1] if clocks else previous_order


def native_edge(row,address):
    peer=sides(row)
    other=peer['to'] if peer['from']==address else peer['from']
    successful=row.get('status')=='ok' or (row.get('success') is True and row.get('error') is None)
    if not successful or int(row.get('value') or 0)<=0 or not other or other==address:
        return None
    info=row.get('to' if peer['from']==address else 'from') or {}
    # EIP-7702 EOAs can have is_contract=true. Never silently call those services.
    delegated=info.get('proxy_type')=='eip7702'
    return {'peer':other,'direction':'out' if peer['from']==address else 'in',
            'valueWei':str(int(row['value'])),'timestamp':row.get('timestamp'),
            'timeClass':temporal(row),'isContractReported':info.get('is_contract'),
            'isDelegatedAccountReported':delegated,'nameReported':info.get('name'),
            'transactionHash':row.get('hash') or row.get('transaction_hash'),
            'publicTagsReported':info.get('public_tags'),'metadataReported':info.get('metadata'),
            'indexerClaimOnly':True,'ownershipProven':False}


class HistoryReader(Reader):
    def __init__(self,out,fetch,limit,delay,repo):
        super().__init__(out,fetch,limit,delay)
        self.reused=[];self.first={}
        p=repo/'challenge7-candidate-affiliation-data/public-page-check.json'
        prior=json.loads(p.read_text())
        for source in prior['responsesUsed']:
            path=Path(source['path'])
            if repo not in path.resolve().parents or digest(path)!=source['sha256']:
                raise ValueError('frozen first-page path/hash disagreement')
            env=json.loads(path.read_text())
            if (env['url']!=source['url'] or env['request'] is not None or env['httpStatus']!=200
                    or hashlib.sha256(env['rawUtf8'].encode()).hexdigest()!=env['responseBytesSha256']
                    or json.loads(env['rawUtf8'])!=env['response']):
                raise ValueError('frozen first-page original response disagreement')
            self.first[source['url']]=(env['response'],source)

    def get(self,url):
        parsed=urllib.parse.urlparse(url)
        if parsed.scheme!='https' or parsed.netloc not in ('eth.blockscout.com','base.blockscout.com'):
            raise ValueError('only the two explicit public indexer hosts allowed')
        parts=parsed.path.split('/')
        if (len(parts)!=6 or parts[:4]!=['','api','v2','addresses']
                or parts[4].lower() not in {CANDIDATE,*SEEDS}
                or parts[5] not in ('transactions','token-transfers','internal-transactions')):
            raise ValueError('request expands beyond candidate/disclosed seeds')
        if url in self.first:
            value,source=self.first[url];self.reused.append(source);return value
        return self.request(url)


def feeds():
    result=[(chain,CANDIDATE,kind) for chain in HOSTS for kind in
            ('transactions','token-transfers','internal-transactions')]
    result += [('Ethereum',address,kind) for address in SEEDS for kind in
               ('transactions','internal-transactions')]
    return result


def collect(reader,chain,address,kind):
    base=HOSTS[chain]+'/api/v2/addresses/'+address+'/'+kind
    url=base;seen_urls=set();rows={};clock=None;pages=0
    while True:
        if url in seen_urls: raise ValueError('cursor loop detected')
        seen_urls.add(url)
        value=reader.get(url)
        items,cursor,clock=validate_page(value,address,kind,clock)
        pages+=1;added=0
        for item in items:
            key=item_id(item,kind)
            if key not in rows: rows[key]=item;added+=1
        print(chain+' '+address[:10]+' '+kind+' page='+str(pages)+
              ' unique='+str(len(rows))+' next='+str(cursor is not None),flush=True)
        if cursor is None:
            return {'chain':chain,'address':address,'kind':kind,'rows':list(rows.values()),
                    'pages':pages,'indexerPaginationComplete':True}
        if pages>1 and added==0: raise ValueError('page adds no new events')
        url=base+'?'+urllib.parse.urlencode(sorted(cursor.items()),doseq=True)


def analyze(results):
    contacts=[];ens=[];funding={};candidate_peers=defaultdict(list);seed_peers=defaultdict(list)
    coverage=[]
    for feed in results:
        chain,address,kind=feed['chain'],feed['address'],feed['kind']
        coverage.append({k:feed[k] for k in ('chain','address','kind','pages','indexerPaginationComplete')}
                        | {'uniqueRows':len(feed['rows']),
                           'temporalCounts':dict(Counter(temporal(r) for r in feed['rows']))})
        early=[]
        for row in feed['rows']:
            pair=sides(row);other=pair['to'] if pair['from']==address else pair['from']
            if address==CANDIDATE and other in SEEDS:
                contacts.append({'chain':chain,'kind':kind,'seed':other,'row':row,
                    'timeClass':temporal(row),'evidenceClass':
                    'token-log-claimed-contact' if kind=='token-transfers' else 'indexed-execution-contact',
                    'ownershipProven':False})
            if kind=='token-transfers':
                contract=str((row.get('token') or {}).get('address_hash') or '').lower()
                if chain=='Ethereum' and contract in ENS_CONTRACTS:
                    ens.append({'chain':chain,'contractRole':ENS_CONTRACTS[contract],'row':row,
                                'timeClass':temporal(row),'ownershipAssociationProven':False})
                continue
            edge=native_edge(row,address)
            if edge:
                edge.update(chain=chain,subject=address,kind=kind)
                if edge['direction']=='in':early.append(edge)
                if edge['timeClass']=='pre-target':
                    (candidate_peers if address==CANDIDATE else seed_peers)[(chain,other)].append(edge)
        if address==CANDIDATE:
            funding[chain+':'+kind]=sorted(early,key=lambda r:r['timestamp'] or '9999')[:10]
    overlap=[]
    for key in candidate_peers.keys() & seed_peers.keys():
        left,right=candidate_peers[key],seed_peers[key]
        all_edges=left+right
        service=any((r.get('isContractReported') is True and not r.get('isDelegatedAccountReported'))
                    or r.get('nameReported') or r.get('publicTagsReported') or r.get('metadataReported')
                    for r in all_edges)
        overlap.append({'chain':key[0],'peer':key[1],'candidateEdges':left,'seedEdges':right,
                        'serviceOrNamedPeerReported':service,
                        'ownershipProven':False,'rarePeerDegreeVerified':False})
    return {'coverage':coverage,'directSeedContacts':contacts,'ensCustodyEvents':ens,
            'earliestNativeIncomingByFeed':funding,'sharedPreTargetValuePeers':overlap,
            'candidateHistoriesComplete':sum(r['address']==CANDIDATE for r in results)==6,
            'allDeclaredFeedsComplete':len(results)==len(feeds()),
            'targetPrivateSpendLink':False,'associationProven':False,'challengeSolved':False,
            'warning':'Complete means indexer pagination only, Ethereum/Base scoped feeds. Token logs may '
                      'spoof peers; named services/exchanges/routers and EIP7702 delegates do not prove ownership.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fetch',action='store_true');p.add_argument('--max-http-calls',type=int,default=100)
    p.add_argument('--delay',type=float,default=3)
    p.add_argument('--omit-timed-out-f9-internals',action='store_true',
                   help='Explicitly leave the twice-timed-out F9 internal feed unresolved; finish other declared feeds. Not for 429/auth failures.')
    a=p.parse_args()
    if not 0<=a.max_http_calls<=160 or a.delay<3:raise ValueError('bounded paced scope required')
    repo=Path(__file__).resolve().parents[1];out=repo/'challenge7-candidate-history-data'
    if out.is_symlink():raise ValueError('output symlink not allowed')
    reader=HistoryReader(out,a.fetch,a.max_http_calls,a.delay,repo)
    results=[];stopped=None;omitted=[]
    try:
        for chain,address,kind in feeds():
            if a.omit_timed_out_f9_internals and (chain,address,kind)==(
                    'Ethereum','0xf9df529961bf8d10fa026ce7a931648bf89b3593','internal-transactions'):
                omitted.append({'chain':chain,'address':address,'kind':kind,
                                'reason':'explicitly omitted after two read timeouts; unresolved, not an empty feed'})
                continue
            results.append(collect(reader,chain,address,kind))
    except Exception as exc:
        stopped=str(exc)  # Global stop on 429/auth/cap, never switch providers to bypass it.
    analysis=analyze(results);analysis['stopped']=stopped;analysis['omittedFeeds']=omitted
    write_rows(out/'completed-feeds.jsonl',results)
    dump(out/'analysis.json',analysis)
    dump(out/'manifest.json',{'stopped':stopped,'omittedFeeds':omitted,'newHttpCalls':reader.calls,
        'responsesUsed':reader.index,'frozenResponsesReused':reader.reused,
        'scriptSha256':digest(Path(__file__)),'analysisSha256':digest(out/'analysis.json'),
        'feedsSha256':digest(out/'completed-feeds.jsonl'),'challengeSolved':False})
    print(json.dumps({'completedFeeds':len(results),'candidateHistoriesComplete':analysis['candidateHistoriesComplete'],
        'newHttpCalls':reader.calls,'directSeedContacts':len(analysis['directSeedContacts']),
        'ensCustodyEvents':len(analysis['ensCustodyEvents']),
        'sharedValuePeers':len(analysis['sharedPreTargetValuePeers']),'stopped':stopped},indent=2))
    if stopped:raise SystemExit(2)


if __name__=='__main__':main()
