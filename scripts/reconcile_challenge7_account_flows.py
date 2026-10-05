#!/usr/bin/env python3
"""Reconcile scoped incoming/outgoing Intents events, without assigning fungible funds.

Public read-only, cache-first, separately checkpointed. Incoming inventory is
frozen from the completed origin pass; outgoing histories have no amount/date
lower bound. All indexed rows require matching successful NEP245 execution.
Balances and account reuse never establish a Zcash spent-note link.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from investigate_challenge7_account_links import SUCCESS, load_trace, timestamp_ns
from trace_challenge7_free_near import CheckpointStop, digest, normalize
from trace_challenge7_user_origins import Reader, SHARED, CUTOFF_NS, TRANSFERS_API, TX_API, trusted_logs


def validate_outgoing(value, spec, previous_token, previous_order=None):
    if not isinstance(value, dict) or not isinstance(value.get("transfers"), list):
        raise ValueError("unexpected outgoing response shape")
    rows = value["transfers"]
    order = []
    for r in rows:
        if (r.get("account_id") != spec["account_id"] or int(r["amount"]) >= 0
                or r.get("asset_id") != spec["asset_id"]
                or int(r["block_timestamp"]) >= int(spec["to_timestamp_ms"])*1000000):
            raise ValueError("outgoing row outside account/asset/direction/time scope")
        order.append((int(r["block_timestamp"]), int(r["transfer_index"])))
    if order != sorted(order) or (order and previous_order is not None and order[0] <= previous_order):
        raise ValueError("outgoing order/continuation mismatch")
    token = value.get("resume_token")
    if token is not None and (token == previous_token or not rows):
        raise ValueError("nonadvancing outgoing cursor")
    return rows, token, order[-1] if order else previous_order


def event_ledger(trace, account, assets, contract="intents.near"):
    """One signed entry per NEP245 item/token/account-side, retaining integers."""
    calls = {c["receiptId"]: c for c in trace["calls"] if c["source"] == "receipt"}
    result = []
    for log in trusted_logs(trace, contract):
        e = log["decoded"]
        if e.get("standard") != "nep245" or e.get("event") not in ("mt_mint", "mt_burn", "mt_transfer"):
            continue
        kind = e["event"]
        clock = calls.get(log["receiptId"], {})
        for item_index, item in enumerate(e.get("data") or []):
            tokens, amounts = item.get("token_ids") or [], item.get("amounts") or []
            if len(tokens) != len(amounts):
                raise ValueError("NEP245 token/amount length mismatch")
            sides = []
            if kind == "mt_transfer":
                if item.get("new_owner_id") == account:
                    sides.append((1, item.get("old_owner_id")))
                if item.get("old_owner_id") == account:
                    sides.append((-1, item.get("new_owner_id")))
            elif item.get("owner_id") == account:
                sides.append((1 if kind == "mt_mint" else -1, None))
            for token_index, (token, amount) in enumerate(zip(tokens, amounts)):
                if token not in assets:
                    continue
                if int(amount) < 0:
                    raise ValueError("negative unsigned NEP245 event amount")
                for sign, counterparty in sides:
                    if not amount or int(amount) == 0:
                        continue
                    if clock.get("blockTimestampNs") is None:
                        raise ValueError("executed account event lacks precise clock")
                    if int(clock["blockTimestampNs"]) >= CUTOFF_NS:
                        continue
                    result.append({"nearRoot": trace["nearTransactionHash"], "receiptId": log["receiptId"],
                                   "logIndex": log["index"], "itemIndex": item_index, "tokenIndex": token_index,
                                   "account": account, "token": token, "amountRaw": str(sign*int(amount)),
                                   "counterparty": counterparty, "event": kind, "memo": item.get("memo"),
                                   "blockTimestampNs": str(clock["blockTimestampNs"]),
                                   "blockTime": clock.get("blockTime"), "blockHeight": clock.get("blockHeight")})
    return result


def event_key(row, indexed=False):
    return (row["receipt_id"] if indexed else row["receiptId"],
            int(row["log_index"] if indexed else row["logIndex"]),
            row["asset_id"].split(":",2)[2] if indexed else row["token"],
            str(int(row["amount"] if indexed else row["amountRaw"])),
            row.get("other_account_id") if indexed else row.get("counterparty"),
            str(int(row["block_timestamp"] if indexed else row["blockTimestampNs"])))


def reconcile_rows(rows, events):
    expected, observed = Counter(), Counter()
    malformed = []
    for r in rows:
        if r.get("log_index") is None:
            malformed.append(r)
        else:
            expected[event_key(r, True)] += 1
    for e in events:
        observed[event_key(e)] += 1
    return {"indexedRowsWithoutLogIndex": malformed,
            "indexedEventsMissingInExecution": [{"key": list(k), "count": v} for k,v in (expected-observed).items()],
            "executedEventsMissingInIndex": [{"key": list(k), "count": v} for k,v in (observed-expected).items()],
            "exactMultisetMatch": not malformed and expected == observed,
            "indexedRows": len(rows), "executedEntries": len(events)}


def balance_audit(rows):
    """Audit signed sums against reported block balances; preserve inferred opening.

    Provider balance snapshots are controls, not independently verified state.
    No FIFO or tracing heuristic is used to attribute fungible units.
    """
    by_asset = defaultdict(list)
    for row in rows:
        by_asset[row["asset_id"]].append(row)
    result = []
    for asset, items in sorted(by_asset.items()):
        blocks = defaultdict(list)
        for row in sorted(items, key=lambda r:(int(r["block_timestamp"]),int(r["transfer_index"]))):
            blocks[int(row["block_height"])].append(row)
        opening, running, mismatches, negative = None, None, [], []
        for height, group in sorted(blocks.items()):
            net = sum(int(r["amount"]) for r in group)
            starts = {int(r["start_of_block_balance"]) for r in group if r.get("start_of_block_balance") is not None}
            ends = {int(r["end_of_block_balance"]) for r in group if r.get("end_of_block_balance") is not None}
            if running is None:
                if len(starts) == 1:
                    opening = next(iter(starts))
                elif len(ends) == 1:
                    opening = next(iter(ends))-net
                if opening is not None:
                    running = opening
            if len(starts)>1 or len(ends)>1:
                mismatches.append({"height":height,"reason":"conflicting reported block balances","starts":sorted(starts),"ends":sorted(ends)})
            if running is not None:
                if starts and starts != {running}:
                    mismatches.append({"height":height,"reason":"start balance differs from executed sum","computed":str(running),"reported":sorted(starts)})
                for row in group:
                    running += int(row["amount"])
                    if running < 0:
                        negative.append({"receiptId":row["receipt_id"],"height":height,"runningBalanceRaw":str(running)})
                if ends and ends != {running}:
                    mismatches.append({"height":height,"reason":"end balance differs from executed sum","computed":str(running),"reported":sorted(ends)})
        result.append({"asset":asset,"indexedRows":len(items),"firstTimeNs":min(int(r["block_timestamp"]) for r in items),
                       "incomingRaw":str(sum(int(r["amount"]) for r in items if int(r["amount"])>0)),
                       "outgoingRaw":str(-sum(int(r["amount"]) for r in items if int(r["amount"])<0)),
                       "openingBalanceRaw":None if opening is None else str(opening),
                       "closingBalanceRaw":None if running is None else str(running),
                       "blockBalanceMismatches":mismatches,"negativeRunningBalances":negative,
                       "warning":"Opening inferred from earliest reported balance, not independently proved historical state or exclusive funding allocation."})
    return result


def nep413_hash(signed):
    """Hash original message bytes, not reserialized parsed JSON; NEP-413."""
    if signed.get("standard") != "nep413":
        raise ValueError("unsupported signed message standard")
    payload = signed["payload"]
    def string(value):
        if not isinstance(value, str):
            raise ValueError("NEP-413 string required; preserve original message")
        encoded = value.encode("utf-8")
        return struct.pack("<I", len(encoded)) + encoded
    nonce = base64.b64decode(payload["nonce"], validate=True)
    if len(nonce) != 32:
        raise ValueError("NEP-413 nonce must contain 32 bytes")
    callback = payload.get("callbackUrl")
    serialized = (struct.pack("<I", 2**31 + 413) + string(payload["message"])
                  + nonce + string(payload["recipient"])
                  + (b"\0" if callback is None else b"\1" + string(callback)))
    hashed = hashlib.sha256(serialized).digest()
    number, encoded = int.from_bytes(hashed, "big"), ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while number:
        number, digit = divmod(number, 58)
        encoded = alphabet[digit] + encoded
    return "1" * (len(hashed) - len(hashed.lstrip(b"\0"))) + encoded


def accepted_intents(trace, account, contract="intents.near"):
    result = []
    executed = [l for l in trusted_logs(trace,contract)
                if l["decoded"].get("standard")=="dip4" and l["decoded"].get("event")=="intents_executed"]
    for call in trace["calls"]:
        if (call["source"] != "receipt" or call["receiver"] != contract or call["method"] != "execute_intents"
                or call["executionStatus"] not in SUCCESS):
            continue
        raw_args = json.loads(base64.b64decode(call["argsBase64"], validate=True))
        for signed in raw_args.get("signed") or []:
            payload = signed["payload"]
            payload = json.loads(payload) if isinstance(payload, str) else payload
            message = payload.get("message", payload)
            message = json.loads(message) if isinstance(message, str) else message
            if isinstance(message,dict) and message.get("signer_id")==account:
                intent_hash = nep413_hash(signed)
                matches = [{"logIndex":l["index"], **item} for l in executed
                           if l["receiptId"]==call["receiptId"] for item in l["decoded"].get("data") or []
                           if item.get("account_id")==account and item.get("intent_hash")==intent_hash
                           and ("nonce" not in item or item["nonce"]==signed["payload"]["nonce"])]
                if len(matches) != 1:
                    raise ValueError("signed NEP-413 hash lacks exactly one matching accepted execution event")
                result.append({"nearRoot":trace["nearTransactionHash"],"receiptId":call["receiptId"],
                               "blockTime":call["blockTime"],"blockTimestampNs":call["blockTimestampNs"],
                               "publicKey":signed.get("public_key"),"standard":signed.get("standard"),"message":message,
                               "intentHash":intent_hash,"nonce":signed["payload"]["nonce"],
                               "acceptedEvent":matches[0],"originalMessageHashMatched":True,
                               "signatureIndependentlyVerified":False,
                               "dip4Events":[l["decoded"] for l in trusted_logs(trace,contract) if l["receiptId"]==call["receiptId"] and l["decoded"].get("standard")=="dip4"]})
    return result


def request_hash(url, body):
    encoded = b"" if body is None else json.dumps(body,sort_keys=True,separators=(",",":")).encode()
    return hashlib.sha256(url.encode()+b"\n"+encoded).hexdigest()


class ReusingReader(Reader):
    def __init__(self, args):
        super().__init__(args.output_dir,args.fetch,args.max_http_calls,args.delay)
        self.reused = {}
        self.old_dirs = [args.origin_dir,args.case_dir,args.branch_dir]

    def request(self,url,body=None):
        name = request_hash(url,body)+".json"
        for directory in self.old_dirs:
            path = directory/"http-responses"/name
            if path.exists():
                envelope = json.loads(path.read_text())
                if envelope["url"]!=url or envelope.get("request")!=body or digest_utf8(envelope)!=envelope["responseBytesSha256"] or json.loads(envelope["rawUtf8"])!=envelope["response"]:
                    raise ValueError("reused original response request/bytes/parsed value disagreement")
                self.reused[str(path.resolve())]=digest(path)
                return envelope["response"]
        return super().request(url,body)


def digest_utf8(envelope):
    return hashlib.sha256(envelope["rawUtf8"].encode()).hexdigest()


def investigate(args):
    for d in (args.origin_dir,args.case_dir,args.branch_dir,args.ledger_dir):
        if args.output_dir.resolve()==d.resolve() or d.resolve() in args.output_dir.resolve().parents:
            raise ValueError("output must be separate from frozen inputs")
    args.output_dir.mkdir(parents=True,exist_ok=True)
    source_manifest=json.loads((args.origin_dir/"manifest.json").read_text())
    source=json.loads((args.origin_dir/"analysis.json").read_text())
    if source_manifest.get("stopped") or source_manifest["analysisSha256"]!=digest(args.origin_dir/"analysis.json") or source_manifest["incomingSha256"]!=digest(args.origin_dir/"incoming-transfers.jsonl") or source_manifest["treesSha256"]!=digest(args.origin_dir/"trees.jsonl"):
        raise ValueError("origin inputs incomplete or manifest hashes disagree")
    incoming=[json.loads(s) for s in (args.origin_dir/"incoming-transfers.jsonl").read_text().splitlines()]
    assets=set(source["incomingInventory"]["tokenIds"])
    reader=ReusingReader(args)
    db=sqlite3.connect("file:"+str((args.ledger_dir/"ledger.sqlite3").resolve())+"?mode=ro",uri=True)
    trees, used, outgoing = {},{},[]
    result={"challengeSolved":False,"outgoingScopes":[],"listingComplete":False,"executionReconciliationComplete":False,
            "assetScope":sorted(assets),"account":SHARED,"cutoffNs":str(CUTOFF_NS)}
    stopped="unexpected failure before completion"
    for path in (args.origin_dir/"trees.jsonl",args.case_dir/"funding-traces.jsonl",args.branch_dir/"bridge-deposit-traces.jsonl"):
        if path.exists():
            reader.reused[str(path.resolve())]=digest(path)
            for line in path.read_text().splitlines():
                t=json.loads(line)
                trees[t["nearTransactionHash"]]=t
    for path in (args.output_dir/"http-responses").glob("*.json"):
        env=json.loads(path.read_text())
        if env["url"]==TX_API:
            if digest_utf8(env)!=env["responseBytesSha256"] or json.loads(env["rawUtf8"])!=env["response"]:
                raise ValueError("cached raw-tree original bytes disagree")
            for entry in env["response"].get("transactions") or []:
                trees[entry["transaction"]["hash"]]=normalize(entry)
            reader.reused[str(path.resolve())]=digest(path)

    def obtain(hashes):
        missing=[]
        for h in sorted(set(hashes)):
            if not trees.get(h):
                trees[h]=load_trace(db,h,{})
                if trees[h]:
                    meta=json.loads(db.execute("SELECT data FROM roots WHERE hash=?",(h,)).fetchone()[0])
                    path=Path(meta["sourceResponse"])
                    reader.reused[str(path.resolve())]=digest(path)
                else:
                    missing.append(h)
        if len(missing)>args.max_new_roots:
            raise CheckpointStop(f"new-root cap: {len(missing)} > {args.max_new_roots}")
        print(f"execution roots={len(set(hashes))} missing={len(missing)}",flush=True)
        for offset in range(0,len(missing),20):
            batch=missing[offset:offset+20]
            value=reader.request(TX_API,{"tx_hashes":batch})
            for entry in value.get("transactions") or []:
                h=entry["transaction"]["hash"]
                if h not in batch:
                    raise ValueError("unrequested root returned")
                trees[h]=normalize(entry)
            if any(not trees.get(h) for h in batch):
                raise CheckpointStop("batch missing requested root; no complete-ledger claim")
            print(f"executions new={min(offset+20,len(missing))}/{len(missing)}",flush=True)
        for h in sorted(set(hashes)):
            if not trees[h]["treeReferencesComplete"]:
                raise CheckpointStop("incomplete execution tree: "+h)
            used[h]=trees[h]
        return list(used.values())

    try:
        for asset in sorted(assets):
            spec={"account_id":SHARED,"asset_id":"nep245:intents.near:"+asset,"direction":"sender",
                  "desc":False,"to_timestamp_ms":CUTOFF_NS//1000000,"limit":100}
            scope={"spec":spec,"pages":0,"rows":0,"listingComplete":False}
            result["outgoingScopes"].append(scope)
            token,order=None,None
            for page in range(args.max_pages):
                response=reader.request(TRANSFERS_API,{**spec,**({"resume_token":token} if token is not None else {})})
                rows,token,order=validate_outgoing(response,spec,token,order)
                outgoing.extend(rows)
                scope.update({"pages":page+1,"rows":scope["rows"]+len(rows),"nextToken":token})
                print(f"outgoing {asset} page={page+1} rows={len(rows)} complete={token is None}",flush=True)
                if token is None:
                    scope["listingComplete"]=True
                    break
            if token is not None:
                raise CheckpointStop("per-asset outgoing page cap; resume cached pages")
        result["listingComplete"]=True
        ledger=sorted(incoming+outgoing,key=lambda r:(int(r["block_timestamp"]),int(r["transfer_index"])))
        identities=[(r["receipt_id"],r["asset_id"],int(r["transfer_index"])) for r in ledger]
        if len(identities)!=len(set(identities)):
            raise ValueError("duplicate incoming/outgoing inventory entry")
        result["balanceAudit"]=balance_audit(ledger)
        result["incomingRows"]=len(incoming)
        result["outgoingRows"]=len(outgoing)
        if any(not r.get("transaction_id") for r in ledger):
            raise CheckpointStop("missing indexed transaction root; receipt lookup required")
        traces=obtain([r["transaction_id"] for r in ledger])
        events=[e for t in traces for e in event_ledger(t,SHARED,assets)]
        result["executionReconciliation"]=reconcile_rows(ledger,events)
        result["executedEvents"]=events
        result["acceptedInstructions"]=[i for t in traces for i in accepted_intents(t,SHARED)]
        result["executionReconciliationComplete"]=result["executionReconciliation"]["exactMultisetMatch"]
        # Do not declare completion when an event inventory disagrees, even if
        # all requests returned successfully. Retain both sides for diagnosis.
        if not result["executionReconciliationComplete"]:
            raise CheckpointStop("indexed/executed event multisets differ; diagnose before attribution")
        result["milestones"]=[]
        for origin in source["connectorOrigins"]:
            cutoff=timestamp_ns(origin["blockTime"])
            token="nep141:"+origin["token"]
            earlier=[r for r in ledger if r["asset_id"]=="nep245:intents.near:"+token and int(r["block_timestamp"])<cutoff]
            same=[r for r in ledger if r["asset_id"]=="nep245:intents.near:"+token and int(r["block_timestamp"])==cutoff]
            result["milestones"].append({"originNonce":origin["originNonce"],"time":origin["blockTime"],"token":token,
                "earlierNetRaw":str(sum(int(r["amount"]) for r in earlier)),"sameClockEntries":same,
                "warning":"Earlier indexed net is not an exclusive-funder allocation or within-receipt ordering proof."})
    except (CheckpointStop,OSError,ValueError,KeyError,TypeError) as exc:
        stopped=str(exc)
        print("checkpoint stop: "+stopped,flush=True)
    else:
        stopped=None
    finally:
        db.close()
        write_rows(args.output_dir/"outgoing-transfers.jsonl",outgoing)
        write_rows(args.output_dir/"trees.jsonl",[used[h] for h in sorted(used)])
        dump(args.output_dir/"analysis.json",result)
        dump(args.output_dir/"manifest.json",{"createdAt":datetime.now(timezone.utc).isoformat(),"stopped":stopped,
            "challengeSolved":False,"newHttpCalls":reader.calls,"responsesUsed":reader.index,"reusedInputHashes":reader.reused,
            "originAnalysisSha256":digest(args.origin_dir/"analysis.json"),"originManifestSha256":digest(args.origin_dir/"manifest.json"),
            "scriptSha256":digest(Path(__file__)),"analysisSha256":digest(args.output_dir/"analysis.json"),
            "outgoingSha256":digest(args.output_dir/"outgoing-transfers.jsonl"),"treesSha256":digest(args.output_dir/"trees.jsonl")})
    print(f"done: {args.output_dir/'analysis.json'}; outgoing={len(outgoing)} stopped={stopped}",flush=True)
    return 2 if stopped else 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--origin-dir",type=Path,default=Path("challenge7-user-origin-data"))
    p.add_argument("--case-dir",type=Path,default=Path("challenge7-account-link-data"))
    p.add_argument("--branch-dir",type=Path,default=Path("challenge7-public-branch-data"))
    p.add_argument("--ledger-dir",type=Path,default=Path("challenge7-withdrawal-ledger-data"))
    p.add_argument("--output-dir",type=Path,default=Path("challenge7-account-flow-data"))
    p.add_argument("--fetch",action="store_true")
    p.add_argument("--max-http-calls",type=int,default=80)
    p.add_argument("--max-new-roots",type=int,default=1000)
    p.add_argument("--max-pages",type=int,default=15)
    p.add_argument("--delay",type=float,default=10)
    a=p.parse_args()
    if min(a.max_http_calls,a.max_new_roots,a.max_pages)<1 or a.delay<0:
        p.error("positive caps and nonnegative pacing required")
    raise SystemExit(investigate(a))


if __name__=="__main__":
    main()
