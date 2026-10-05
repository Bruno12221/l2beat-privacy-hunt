#!/usr/bin/env python3
"""Verify explicit funding IDs for the selected new exact-pair origins.

Only public reads: two memo-identified Base deposits and two proof-identified
Zcash outpoints. Raw Zcash bytes come from executed connector deposit proofs.
No wallet-ownership claim, solver allocation, private-note link, or signing.
"""
from __future__ import annotations
import argparse,json,subprocess
from pathlib import Path
from analyze_challenge7_baseline import dump,write_rows
from reconcile_challenge7_account_flows import ReusingReader
from investigate_challenge7_account_links import timestamp_ns
from trace_challenge7_free_near import CheckpointStop,digest
from trace_challenge7_user_origins import connector_deposit_links,ZEC_API
from verify_challenge7_origin_deposits import rpc_batch,verify_receipt

BASE_RPC='https://mainnet.base.org'
ANCHOR=3488703


def verify_deposit_output(link,detail,decoded,mint_time):
    if (detail.get('txid')!=link['zecTxid'] or decoded.get('txid')!=link['zecTxid'] or not decoded.get('ok')
            or detail.get('isCanonical') is not True or int(detail['blockHeight'])>ANCHOR
            or detail.get('blockHash')!=link['proofBlockHash']):
        raise ValueError('deposit raw/indexed identity, canonicality, anchor or accepted proof block disagreement')
    if int(detail['blockTime'])*1000000000>timestamp_ns(mint_time):raise ValueError('deposit mined after executed mint')
    outputs=[o for o in decoded.get('transparentOutputs') or [] if o['index']==link['vout']]
    indexed=[o for o in detail.get('outputs') or [] if o['vout_index']==link['vout']]
    if (len(outputs)!=1 or len(indexed)!=1 or int(outputs[0]['valueZat'])!=int(link['grossDepositZat'])
            or int(indexed[0]['value'])!=int(link['grossDepositZat'])):
        raise ValueError('deposit exact raw/indexed outpoint value disagreement')
    return {'outpoint':f"{link['zecTxid']}:{link['vout']}",'valueZat':link['grossDepositZat'],
            'scriptPubKeyHex':outputs[0]['scriptPubKeyHex'],'rawOutpointVerified':True,
            'warning':'Specific deposit outpoint and account credit, not private-input ancestry or target consumption.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir',type=Path,default=Path('challenge7-new-exact-origins-data'))
    p.add_argument('--output-dir',type=Path,default=Path('challenge7-new-exact-funding-data'))
    p.add_argument('--decoder',type=Path,default=Path('decoder/target/release/note_ledger'))
    p.add_argument('--fetch',action='store_true');p.add_argument('--max-http-calls',type=int,default=8)
    p.add_argument('--delay',type=float,default=3)
    a=p.parse_args()
    if not 0<=a.max_http_calls<=8 or a.delay<1 or a.output_dir.resolve()==a.source_dir.resolve():raise ValueError('bounded separate paced scope required')
    a.origin_dir=Path('challenge7-user-origin-data');a.case_dir=Path('challenge7-account-link-data');a.branch_dir=Path('challenge7-public-branch-data')
    a.output_dir.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((a.source_dir/'manifest.json').read_text())
    for file,key in [('trees.jsonl','treesSha256'),('mint-deposits.jsonl','mintDepositsSha256'),('cases.jsonl','casesSha256')]:
        if digest(a.source_dir/file)!=manifest[key]:raise ValueError('source evidence hash mismatch')
    if manifest.get('stopped') or manifest['publiclyVerifiedPayouts']!=8 or not manifest['incomingHistoriesComplete']:
        raise ValueError('completed eight-payout public origin scope required')
    trees={r['nearTransactionHash']:r for r in map(json.loads,(a.source_dir/'trees.jsonl').open())}
    deposits=list(map(json.loads,(a.source_dir/'mint-deposits.jsonl').open()))
    base=[];zec=[]
    for m in deposits:
        for d in m['externalDeposits']:
            if d['memo'].get('networkType')=='eth' and str(d['memo'].get('chainId'))=='8453':
                base.append({**d,'intentsAccount':m['account'],'nearRoot':m['nearRoot'],'mintReceipt':m['receiptId']})
        if m['token']=='nep141:zec.omft.near':
            for link in connector_deposit_links(trees[m['nearRoot']],m['receiptId'],'intents.near',m['amountRaw'],m['account']):
                zec.append({**link,'mintTime':m['blockTime']})
    if len(base)!=2 or len(zec)!=2:raise ValueError('explicit two-Base/two-Zcash scope changed; review rather than expand silently')
    reader=ReusingReader(a);base_results=[];zec_results=[];stopped='unexpected failure before completion'
    try:
        queries=[('eth_chainId',[])]+[(method,[d['memo']['txHash']]) for d in base for method in ('eth_getTransactionByHash','eth_getTransactionReceipt')]
        values=rpc_batch(reader,queries,BASE_RPC)
        if int(values[0],16)!=8453:raise ValueError('Base RPC chain identity mismatch')
        pairs=[(values[1+2*i],values[2+2*i]) for i in range(len(base))]
        if any(not tx or not receipt for tx,receipt in pairs):raise CheckpointStop('memo-identified Base transaction/receipt unavailable')
        numbers=sorted({r['blockNumber'] for _,r in pairs})
        blocks=dict(zip(numbers,rpc_batch(reader,[('eth_getBlockByNumber',[n,False]) for n in numbers],BASE_RPC)))
        for d,(tx,receipt) in zip(base,pairs):
            base_results.append(verify_receipt(d,tx,receipt,blocks[receipt['blockNumber']],8453,'base-'))
            print('verified Base deposit='+d['memo']['txHash'],flush=True)
        for link in zec:
            detail=reader.request(f"{ZEC_API}/tx/{link['zecTxid']}")
            packet={'hex':link['rawHex'],'expectedTxid':link['zecTxid'],'allowV4Transparent':True,
                    'blockHeight':detail['blockHeight'],'blockTime':detail['blockTime'],'isCanonical':detail.get('isCanonical')}
            decoded=json.loads(subprocess.run([str(a.decoder.resolve())],input=json.dumps(packet)+'\n',text=True,capture_output=True,check=True,timeout=30).stdout)
            output=verify_deposit_output(link,detail,decoded,link['mintTime'])
            zec_results.append({'link':link,'detail':detail,'decoded':decoded,'verifiedOutput':output})
            print('verified Zcash deposit='+output['outpoint'],flush=True)
        stopped=None
    except (CheckpointStop,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        stopped=str(exc);print('checkpoint: '+stopped,flush=True)
    finally:
        write_rows(a.output_dir/'base-deposits.jsonl',base_results);write_rows(a.output_dir/'zcash-deposits.jsonl',zec_results)
        dump(a.output_dir/'manifest.json',{'challengeSolved':False,'targetPrivateSpendLink':False,'stopped':stopped,
             'sourceManifestSha256':digest(a.source_dir/'manifest.json'),'scriptSha256':digest(Path(__file__)),
             'decoderSha256':digest(a.decoder),'newHttpCalls':reader.calls,'responsesUsed':reader.index,'reusedSources':reader.reused,
             'verifiedBaseDeposits':len(base_results),'verifiedZcashDepositOutpoints':len(zec_results),
             'baseDepositsSha256':digest(a.output_dir/'base-deposits.jsonl'),'zcashDepositsSha256':digest(a.output_dir/'zcash-deposits.jsonl')})
    print(f"{'checkpoint' if stopped else 'done'}: Base={len(base_results)}/2 Zcash={len(zec_results)}/2 newHTTP={reader.calls}",flush=True)
    return 2 if stopped else 0


if __name__=='__main__':raise SystemExit(main())
