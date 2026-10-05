#!/usr/bin/env python3
"""Verify Ethereum transactions explicitly named by preserved NEAR deposits.

No speculative amount search: input hashes come from executed bridge memos.
Cache-only by default; bounded --fetch uses read-only batched Ethereum RPC.
Transaction submitters and ERC20 transfer senders are recorded separately.
"""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump
from investigate_challenge7_account_links import TRANSFER_TOPIC, timestamp_ns
from trace_challenge7_free_near import CheckpointStop, digest
from trace_challenge7_user_origins import Reader, CUTOFF_NS

RPC = "https://ethereum-rpc.publicnode.com"
READ_METHODS = {"eth_chainId", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber"}


def transfer_logs(receipt, token):
    result = []
    for log in receipt.get("logs") or []:
        topics = log.get("topics") or []
        if (log.get("removed") is True or log.get("address", "").lower() != token.lower()
                or len(topics) != 3 or topics[0].lower() != TRANSFER_TOPIC
                or not all(re.fullmatch(r"0x[0-9a-fA-F]{64}", t) for t in topics)
                or any(t[2:26] != "0"*24 for t in topics[1:])
                or not re.fullmatch(r"0x[0-9a-fA-F]{64}", log.get("data", ""))):
            continue
        result.append({"token": token.lower(), "sender": "0x"+topics[1][-40:].lower(),
                       "recipient": "0x"+topics[2][-40:].lower(), "amountRaw": str(int(log["data"], 16)),
                       "logIndex": int(log["logIndex"], 16)})
    return result


def verify_receipt(deposit, tx, receipt, block, chain_id=1, token_prefix="eth-"):
    if (chain_id,token_prefix) not in ((1,"eth-"),(8453,"base-")):
        raise ValueError("unsupported explicitly configured EVM chain/token prefix")
    if deposit["memo"].get("networkType") != "eth" or str(deposit["memo"].get("chainId")) != str(chain_id):
        raise ValueError("deposit memo is not the explicitly configured EVM chain")
    h = deposit["memo"]["txHash"].lower()
    if not tx or not receipt or not block:
        raise ValueError("missing transaction/receipt/block")
    if (tx["hash"].lower() != h or receipt["transactionHash"].lower() != h
            or tx["blockHash"] != receipt["blockHash"] or receipt["blockHash"] != block["hash"]
            or tx["blockNumber"] != receipt["blockNumber"] or receipt["blockNumber"] != block["number"]
            or int(receipt["status"], 16) != 1):
        raise ValueError("transaction hash/status/canonical block disagreement")
    if int(block["timestamp"], 16) * 1_000_000_000 >= CUTOFF_NS:
        raise ValueError("external deposit not before target")
    if int(block["timestamp"],16)*1_000_000_000 > timestamp_ns(deposit["blockTime"]):
        raise ValueError("external transaction after claimed bridge deposit")
    if not deposit["token"].startswith(token_prefix):raise ValueError("deposit token chain prefix mismatch")
    token = deposit["token"].removeprefix(token_prefix)
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", token):
        raise ValueError("unexpected Ethereum token identifier")
    logs = transfer_logs(receipt, token)
    for log in receipt.get("logs") or []:
        if log.get("address", "").lower() == token.lower() and log.get("removed") is not True:
            if (log.get("transactionHash", "").lower() != h or log.get("blockHash") != block["hash"]
                    or log.get("blockNumber") != block["number"]):
                raise ValueError("token log transaction/block identity disagreement")
    exact = [r for r in logs if r["amountRaw"] == deposit["amountRaw"]]
    return {"externalTxHash": h, "chainId": chain_id, "transactionSubmitter": tx["from"].lower(),
            "transactionTo": tx.get("to"), "blockHash": block["hash"], "blockNumber": int(block["number"], 16),
            "blockTime": datetime.fromtimestamp(int(block["timestamp"],16),timezone.utc).isoformat(),
            "tokenTransferLogs": logs, "exactMintAmountTransferMatches": exact,
            "uniqueExactMintAmountTransfer": exact[0] if len(exact) == 1 else None,
            "successfulCanonicalTransaction": True,
            "nearDeposit": deposit,
            "warning": "Exact NEAR bridge memo identifies this successful EVM transaction on the explicitly checked chain. Unique amount log is additional corroboration, not exclusive balance allocation, real-world ownership, or proof of the challenge private spend."}


def rpc_batch(reader, queries, rpc_url=RPC):
    if any(m not in READ_METHODS for m, _ in queries):
        raise ValueError("not an allowed read-only RPC method")
    values = []
    for offset in range(0, len(queries), 20):
        batch = queries[offset:offset+20]
        body = [{"jsonrpc": "2.0", "id": i+1, "method": m, "params": p} for i,(m,p) in enumerate(batch)]
        response = reader.request(rpc_url, body)
        if not isinstance(response, list) or any(v.get("jsonrpc") != "2.0" for v in response):
            raise ValueError("unexpected RPC batch response shape/version")
        by_id = {r["id"]: r for r in response}
        if len(response) != len(batch) or len(by_id) != len(batch) or set(by_id) != set(range(1,len(batch)+1)):
            raise ValueError("RPC batch response IDs missing/duplicated")
        for i in range(1,len(batch)+1):
            if "error" in by_id[i]:
                raise CheckpointStop("RPC error, no provider rotation: " + str(by_id[i]["error"]))
            values.append(by_id[i]["result"])
    return values


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--origin-dir",type=Path,default=Path("challenge7-user-origin-data"))
    p.add_argument("--output-dir",type=Path,default=Path("challenge7-verified-origin-data"))
    p.add_argument("--fetch",action="store_true")
    p.add_argument("--max-http-calls",type=int,default=10)
    p.add_argument("--delay",type=float,default=10)
    a=p.parse_args()
    if a.output_dir.resolve()==a.origin_dir.resolve() or a.max_http_calls<1 or a.delay<0:
        p.error("separate output, positive limit, nonnegative delay required")
    a.output_dir.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((a.origin_dir/"manifest.json").read_text())
    source=json.loads((a.origin_dir/"analysis.json").read_text())
    if manifest.get("stopped") or not source.get("incomingInventory",{}).get("listingComplete"):
        p.error("origin collector unfinished; do not silently verify a partial funding inventory")
    if manifest.get("analysisSha256") != digest(a.origin_dir/"analysis.json"):
        p.error("origin analysis differs from preserved manifest hash")
    r=Reader(a.output_dir,a.fetch,a.max_http_calls,a.delay)
    results={"challengeSolved":False,"ethereumDeposits":[],"unverifiedOtherChains":[],"notExclusiveFunderProof":True}
    stopped="unexpected failure before completion"
    try:
        deposits=[]
        for mint in source.get("explicitExternalDeposits") or []:
            for d in mint["externalDeposits"]:
                if d["memo"].get("networkType")=="eth" and str(d["memo"].get("chainId"))=="1":
                    deposits.append({**d,"nearRoot":mint["nearRoot"],"mintReceipt":mint["receiptId"],"intentsAccount":mint["account"]})
                else:
                    results["unverifiedOtherChains"].append({"nearRoot":mint["nearRoot"],"deposit":d})
        if int(rpc_batch(r,[("eth_chainId",[])])[0],16)!=1:
            raise ValueError("Ethereum RPC chain mismatch")
        hashes=sorted({d["memo"]["txHash"].lower() for d in deposits})
        queries=[(m,[h]) for h in hashes for m in ("eth_getTransactionByHash","eth_getTransactionReceipt")]
        values=rpc_batch(r,queries)
        pairs={h:(values[2*i],values[2*i+1]) for i,h in enumerate(hashes)}
        numbers=sorted({receipt["blockNumber"] for _,receipt in pairs.values() if receipt})
        blocks=dict(zip(numbers,rpc_batch(r,[("eth_getBlockByNumber",[n,False]) for n in numbers])))
        for d in deposits:
            tx,receipt=pairs[d["memo"]["txHash"].lower()]
            results["ethereumDeposits"].append(verify_receipt(d,tx,receipt,blocks[receipt["blockNumber"]]))
        results["transactionSubmitterCounts"]=dict(Counter(v["transactionSubmitter"] for v in results["ethereumDeposits"]))
        results["uniqueAmountTransferSenderCounts"]=dict(Counter(v["uniqueExactMintAmountTransfer"]["sender"] for v in results["ethereumDeposits"] if v["uniqueExactMintAmountTransfer"]))
    except (CheckpointStop,OSError,ValueError,KeyError,TypeError) as exc:
        stopped=str(exc)
        print("checkpoint stop: "+stopped,flush=True)
    else:
        stopped=None
    finally:
        dump(a.output_dir/"analysis.json",results)
        dump(a.output_dir/"manifest.json",{"createdAt":datetime.now(timezone.utc).isoformat(),"stopped":stopped,
                                           "newHttpCalls":r.calls,"responsesUsed":r.index,"challengeSolved":False,
                                           "sourceAnalysisSha256":digest(a.origin_dir/"analysis.json"),"sourceManifestSha256":digest(a.origin_dir/"manifest.json"),
                                           "scriptSha256":digest(Path(__file__)),"analysisSha256":digest(a.output_dir/"analysis.json")})
    print(f"done: {a.output_dir/'analysis.json'}; verified={len(results['ethereumDeposits'])}; stopped={stopped}",flush=True)
    raise SystemExit(2 if stopped else 0)


if __name__=="__main__":
    main()
