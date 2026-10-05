#!/usr/bin/env python3
"""Read-only RPC corroboration of selected candidate funding/ENS history.

Cache-only by default. No attribution from names, services, or private inputs.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump
from trace_challenge7_candidate_history import CANDIDATE, ENS_CONTRACTS, sides
from trace_challenge7_free_near import digest
from trace_challenge7_user_origins import Reader
from verify_challenge7_origin_deposits import rpc_batch, TRANSFER_TOPIC

RPC={'Ethereum':('https://ethereum-rpc.publicnode.com',1),
     'Base':('https://mainnet.base.org',8453)}


def wrapped_names(logs):
    result=[]
    for log in logs:
        topics=log.get('topics') or []
        if (log.get('address','').lower()!='0xd4416b13d2b3a9abae7acd5d6c2bbdbe25686401'
                or len(topics)!=2 or topics[0].lower()!=
                '0x8ce7013e8abebc55c3890a68f5a27c67c3f7efa64e584de5fb22363c606fd340'):
            continue
        data=bytes.fromhex(log['data'][2:])
        if len(data)<160 or int.from_bytes(data[:32],'big')!=128:
            raise ValueError('unexpected NameWrapped ABI')
        n=int.from_bytes(data[128:160],'big');name=data[160:160+n]
        if len(name)!=n:raise ValueError('truncated wrapped name')
        labels=[];i=0
        while i<len(name) and name[i]:
            size=name[i];i+=1
            if size>63 or i+size>len(name):raise ValueError('invalid DNS label')
            labels.append(name[i:i+size].decode('ascii'));i+=size
        if i!=len(name)-1 or not labels:raise ValueError('invalid DNS termination')
        result.append({'name':'.'.join(labels),'node':topics[1],
                       'owner':'0x'+data[44:64].hex(),'historicalEventOnly':True})
    return result


def verify(row,tx,receipt,block,kind,allow_failed_nonce_zero=False):
    h=(row.get('hash') or row['transaction_hash']).lower()
    if not tx or not receipt or not block:
        raise ValueError('missing RPC transaction/receipt/block')
    if (tx['hash'].lower()!=h or receipt['transactionHash'].lower()!=h
            or tx['blockHash']!=receipt['blockHash'] or tx['blockHash']!=block['hash']
            or tx['blockNumber']!=receipt['blockNumber'] or tx['blockNumber']!=block['number']):
        raise ValueError('RPC identity/block/status disagreement')
    success=int(receipt['status'],16)==1
    if not success and not (allow_failed_nonce_zero and kind=='transactions'
                            and tx['from'].lower()==CANDIDATE and int(tx['nonce'],16)==0
                            and int(tx['value'],16)==0):
        raise ValueError('RPC failed transaction cannot corroborate executed funding/custody')
    clock=datetime.fromtimestamp(int(block['timestamp'],16),timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    if row['timestamp'][:19]!=clock:raise ValueError('indexer/RPC clock disagreement')
    pair=sides(row)
    if kind=='transactions' and (tx['from'].lower()!=pair['from']
            or (tx.get('to') or '').lower()!=pair['to'] or int(tx['value'],16)!=int(row['value'])):
        raise ValueError('indexed native transfer differs from RPC transaction')
    logs=[]
    if kind=='token-transfers':
        contract=row['token']['address_hash'].lower()
        if contract not in ENS_CONTRACTS:raise ValueError('nonofficial ENS contract')
        logs=[log for log in receipt['logs'] if log['address'].lower()==contract
              and int(log['logIndex'],16)==row['log_index'] and log.get('removed') is not True]
        if len(logs)!=1:raise ValueError('missing exact ENS receipt log')
        log=logs[0];topics=log['topics'];tid=int(row['total']['token_id'])
        if row['token_type']=='ERC-721':
            valid=(len(topics)==4 and topics[0].lower()==TRANSFER_TOPIC
                   and '0x'+topics[1][-40:].lower()==pair['from']
                   and '0x'+topics[2][-40:].lower()==pair['to'] and int(topics[3],16)==tid)
        else:
            # TransferSingle(address,address,address,uint256,uint256).
            valid=(len(topics)==4 and topics[0].lower()==
                '0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62'
                and '0x'+topics[2][-40:].lower()==pair['from']
                and '0x'+topics[3][-40:].lower()==pair['to']
                and len(log['data'])==130 and int(log['data'][2:66],16)==tid
                and int(log['data'][66:],16)==int(row['total']['value']))
        if not valid:raise ValueError('ENS receipt event differs from indexed custody')
        if (log['transactionHash'].lower()!=h or log['blockHash']!=block['hash']
                or log['blockNumber']!=block['number']):raise ValueError('ENS log block mismatch')
    return {'transactionHash':h,'from':tx['from'].lower(),'to':tx.get('to'),
            'valueWei':str(int(tx['value'],16)),'nonce':int(tx['nonce'],16),
            'timestamp':clock+'Z','blockNumber':int(block['number'],16),
            'blockHash':block['hash'],'receiptSuccess':success,'matchedEnsLogs':logs,
            'indexerSuccessDisagreement':row.get('status')=='ok' and not success,
            'officialEnsContractLogs':[l for l in receipt['logs'] if l['address'].lower() in ENS_CONTRACTS],
            'wrappedNames':wrapped_names(receipt['logs']),
            'kind':kind,'indexerSides':pair,'ownershipAssociationProven':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fetch',action='store_true');a=p.parse_args()
    repo=Path(__file__).resolve().parents[1];src=repo/'challenge7-candidate-history-data'
    manifest=json.loads((src/'manifest.json').read_text())
    if digest(src/'completed-feeds.jsonl')!=manifest['feedsSha256']:raise ValueError('source hash mismatch')
    fs=[json.loads(s) for s in (src/'completed-feeds.jsonl').read_text().splitlines()]
    selected={};reasons={}
    def add(chain,kind,row,reason):
        h=(row.get('hash') or row['transaction_hash']).lower();key=(chain,h,kind)
        selected[key]=row;reasons.setdefault(key,[]).append(reason)
    for f in fs:
        if f['address']!=CANDIDATE:continue
        chain,kind=f['chain'],f['kind'];rows=f['rows']
        if kind=='transactions':
            incoming=[r for r in rows if sides(r)['to']==CANDIDATE and int(r['value'])>0 and r['status']=='ok']
            if incoming:add(chain,kind,min(incoming,key=lambda r:r['timestamp']),'earliest normal native incoming')
            zero=[r for r in rows if sides(r)['from']==CANDIDATE and r.get('nonce')==0 and r['status']=='ok']
            for r in zero:add(chain,kind,r,'first nonce-zero signed transaction')
            for r in rows:
                if r['hash'].lower() in {
                    '0xfd6e5c8d016ab9504af92a7acd9ecb473373443a7b0f7c6e50a3c4ebd6422498',
                    '0xf17edfc9cff633851e848f3c845e44beb9de51f088b71b6544737b91b2a416e6'}:
                    add(chain,kind,r,'known candidate pre-Zcash funding transaction')
        if kind=='token-transfers' and chain=='Ethereum':
            for r in rows:
                if r['token']['address_hash'].lower() in ENS_CONTRACTS:add(chain,kind,r,'official ENS custody event')
    out=src/'rpc-verification';reader=Reader(out,a.fetch,12,3);result={'verified':[],'stopped':None,'challengeSolved':False}
    try:
        for chain,(url,chainid) in RPC.items():
            keys=[k for k in selected if k[0]==chain];hashes=sorted({k[1] for k in keys})
            if not hashes:continue
            vals=rpc_batch(reader,[('eth_chainId',[])]+[(m,[h]) for h in hashes for m in
                           ('eth_getTransactionByHash','eth_getTransactionReceipt')],url)
            if int(vals[0],16)!=chainid:raise ValueError('RPC chain mismatch')
            pairs={h:(vals[1+2*i],vals[2+2*i]) for i,h in enumerate(hashes)}
            numbers=sorted({t['blockNumber'] for t,r in pairs.values() if t})
            blocks=dict(zip(numbers,rpc_batch(reader,[('eth_getBlockByNumber',[n,False]) for n in numbers],url)))
            for key in keys:
                tx,receipt=pairs[key[1]];v=verify(selected[key],tx,receipt,blocks[tx['blockNumber']],key[2],
                    allow_failed_nonce_zero='first nonce-zero signed transaction' in reasons[key])
                result['verified'].append({**v,'chain':chain,'selectionReasons':reasons[key]})
    except Exception as exc:result['stopped']=str(exc)
    dump(out/'analysis.json',result)
    dump(out/'manifest.json',{'sourceFeedsSha256':digest(src/'completed-feeds.jsonl'),
          'sourceStopped':manifest['stopped'],'analysisSha256':digest(out/'analysis.json'),
          'scriptSha256':digest(Path(__file__)),'responsesUsed':reader.index,'newHttpCalls':reader.calls,
          'stopped':result['stopped']})
    print(json.dumps({'verified':len(result['verified']),'stopped':result['stopped'],'calls':reader.calls}))
    if result['stopped']:raise SystemExit(2)


if __name__=='__main__':main()
