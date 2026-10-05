#!/usr/bin/env python3
"""Check all scoped account nzec exits by nonce, plus one declared legacy route.

Public, cache-first, capped reads. Retains a complete local legacy-exit inventory
but only fetches the explicitly selected legacy root. No private-note or owner
attribution, paid APIs, JWT, signing, or modification of previous datasets.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from investigate_challenge7_account_links import SUCCESS, builder_packets, compare_raw_packet, pending_payouts, timestamp_ns
from reconcile_challenge7_account_flows import ReusingReader
from trace_challenge7_free_near import CheckpointStop, digest, normalize
from trace_challenge7_user_origins import OMNI_API, SHARED, TX_API, ZEC_API, descendants, trusted_logs

ANCHOR = 3488703
LEGACY_ROOT = "J5PtgeXxAsedTbpy9ME654AFTxYqGx57UGLQnUgiL2ky"


def modern_exits(analysis, trees):
    result=[]
    for accepted in analysis["acceptedInstructions"]:
        trace=trees[accepted["nearRoot"]]
        for instruction in accepted["message"].get("intents") or []:
            if instruction.get("intent")!="ft_withdraw" or instruction.get("token")!="nzec.bridge.near":
                continue
            if not accepted.get("originalMessageHashMatched"):
                raise ValueError("unverified message-to-accepted-event hash")
            linked=descendants(trace,accepted["receiptId"])
            msg=instruction.get("msg") or {}
            msg=json.loads(msg) if isinstance(msg,str) else msg
            recipient=msg.get("recipient")
            amount=str(int(instruction["amount"]))
            events=[]
            for log in trusted_logs(trace,"omni.bridge.near"):
                m=(log["decoded"].get("InitTransferEvent") or {}).get("transfer_message") or {}
                if (log["receiptId"] in linked and m.get("sender")=="near:intents.near"
                        and m.get("token")=="near:nzec.bridge.near" and m.get("recipient")==recipient
                        and str(m.get("amount"))==amount):
                    events.append({"receiptId":log["receiptId"],"message":m})
            burns=[e for e in analysis["executedEvents"] if e["nearRoot"]==accepted["nearRoot"]
                   and e["receiptId"]==accepted["receiptId"] and e["token"]=="nep141:nzec.bridge.near"
                   and e["event"]=="mt_burn" and e["amountRaw"]=="-"+amount]
            if instruction.get("receiver_id")!="omni.bridge.near" or len(events)!=1 or len(burns)!=1:
                raise ValueError("modern withdrawal lacks unique descendant init and actual burn")
            result.append({"nearRoot":accepted["nearRoot"],"executedReceipt":accepted["receiptId"],
                           "blockTime":accepted["blockTime"],"intentHash":accepted["intentHash"],
                           "requestedReceiver":recipient,"amountRaw":amount,"instruction":instruction,
                           "originNonce":int(events[0]["message"]["origin_nonce"]),"initEvent":events[0],
                           "executedBurn":burns[0],"publicExecutionVerified":True})
    result.sort(key=lambda r:timestamp_ns(r["blockTime"]))
    if len({r["originNonce"] for r in result})!=len(result):
        raise ValueError("duplicate modern origin nonce")
    return result


def legacy_exits(analysis, trees, account=SHARED):
    """Gross DIP4 transfers and net NEP245 settlements deliberately separate."""
    found=[]
    for accepted in analysis["acceptedInstructions"]:
        trace=trees[accepted["nearRoot"]]
        receivers={account}
        gross={}
        for ins in accepted["message"].get("intents") or []:
            amount=(ins.get("tokens") or {}).get("nep141:zec.omft.near")
            if ins.get("intent")=="transfer" and amount:
                receivers.add(ins["receiver_id"])
                gross[ins["receiver_id"]]=str(int(amount))
        for log in trusted_logs(trace,"intents.near"):
            e=log["decoded"]
            if e.get("standard")!="dip4" or e.get("event")!="ft_withdraw":
                continue
            for item in e.get("data") or []:
                memo=item.get("memo") or ""
                if (item.get("account_id") not in receivers or item.get("token")!="zec.omft.near"
                        or item.get("receiver_id")!="zec.omft.near" or not memo.startswith("WITHDRAW_TO:")):
                    continue
                amount=str(int(item["amount"]))
                onward=[c for c in trace["calls"] if c["source"]=="receipt" and c["receiver"]=="zec.omft.near"
                        and c["method"]=="ft_transfer" and c["predecessor"]=="intents.near"
                        and c["executionStatus"] in SUCCESS and c["receiptId"] in descendants(trace,log["receiptId"])
                        and (c.get("args") or {}).get("memo")==memo and str((c.get("args") or {}).get("amount"))==amount]
                burned=[l for l in trusted_logs(trace,"zec.omft.near") if l["receiptId"] in {c["receiptId"] for c in onward}
                        and l["decoded"].get("standard")=="nep141" and l["decoded"].get("event")=="ft_burn"
                        and any(x.get("owner_id")=="intents.near" and x.get("memo")==memo and str(x.get("amount"))==amount
                                for x in l["decoded"].get("data") or [])]
                if len(onward)>1 or len(burned)>1:
                    raise ValueError("ambiguous legacy token self-transfer/burn")
                delegated=[{"receiptId":l["receiptId"],"logIndex":l["index"],**x}
                           for l in trusted_logs(trace,"zec.omft.near")
                           if l["receiptId"] in {c["receiptId"] for c in onward}
                           and l["decoded"].get("standard")=="nep141" and l["decoded"].get("event")=="ft_transfer"
                           for x in l["decoded"].get("data") or []
                           if x.get("old_owner_id")=="intents.near" and x.get("memo")==memo and str(x.get("amount"))==amount]
                net=[e for e in analysis["executedEvents"] if e["nearRoot"]==accepted["nearRoot"]
                     and e["receiptId"]==accepted["receiptId"] and e["token"]=="nep141:zec.omft.near"
                     and e["counterparty"]==item["account_id"] and int(e["amountRaw"])<0]
                found.append({"nearRoot":accepted["nearRoot"],"blockTime":accepted["blockTime"],
                              "requestedReceiver":memo[len("WITHDRAW_TO:"):],"amountRaw":amount,
                              "temporaryAccount":item["account_id"],"withdrawIntentHash":item.get("intent_hash"),
                              "grossTransferRaw":gross.get(item["account_id"]),"netSettlement":net,
                              "withdrawEvent":{"receiptId":log["receiptId"],"logIndex":log["index"],**item},
                              "tokenBurnReceipt":onward[0]["receiptId"] if onward else None,
                              "legacyTokenBurnVerified":len(onward)==1 and len(burned)==1,
                              "publicNearExecutionVerified":len(onward)==1 and bool(burned or delegated),
                              "unverifiedOrFailedTokenStage":not (len(onward)==1 and bool(burned or delegated)),
                              "delegatedTokenTransfers":delegated,
                              "tokenStageOutcome":"legacy-token-burn-verified" if burned else (
                                  "successful-token-transfer-to-other-owner" if delegated else "unverified-token-stage"),
                              "warning":"No explicit Zcash transaction ID in legacy burn; receiver associations need separate qualification."})
    # A root can contain more than one signed shared-account message.
    unique={(r["nearRoot"],r["withdrawEvent"]["receiptId"],r["withdrawIntentHash"]):r for r in found}
    return sorted(unique.values(),key=lambda r:timestamp_ns(r["blockTime"]))


def legacy_transfers(analysis):
    result=[]
    for accepted in analysis["acceptedInstructions"]:
        for ins in accepted["message"].get("intents") or []:
            amount=(ins.get("tokens") or {}).get("nep141:zec.omft.near")
            if ins.get("intent")=="transfer" and amount:
                result.append({"nearRoot":accepted["nearRoot"],"blockTime":accepted["blockTime"],
                               "intentHash":accepted["intentHash"],"receiverAccount":ins["receiver_id"],
                               "grossAmountRaw":str(int(amount)),
                               "warning":"Accepted gross instruction; net settlement and any later withdrawal must be checked separately."})
    return sorted(result,key=lambda r:timestamp_ns(r["blockTime"]))


def validate_omni(value, exit):
    matches=[r for r in value.get("transfers") or [] if r.get("transfer_id")==
             {"type":"nonce","chain":"Near","nonce":exit["originNonce"]}]
    if len(matches)!=1:
        raise ValueError("nonunique or missing exact Omni transfer")
    r=matches[0]
    init=r.get("initialised") or {}
    if (r.get("sender")!="near:intents.near" or r.get("token_id")!="near:nzec.bridge.near"
            or str(r.get("amount"))!=exit["amountRaw"] or r.get("recipient")!=exit["requestedReceiver"]
            or init.get("transaction_hash")!=exit["nearRoot"]
            or (init.get("details") or {}).get("receipt_id")!=exit["initEvent"]["receiptId"]):
        raise ValueError("Omni index disagrees with successful exact origin execution")
    return r


def compare_complete_packet(packet, decoded):
    """Exact serialized private bundle, not just a matching public balance."""
    result=compare_raw_packet(packet,decoded)
    chain=packet.get("chain_specific_data") or {}
    bundles=decoded.get("bundles") or []
    encoded=chain.get("orchard_bundle_bytes")
    if not bundles:
        shielded_match=encoded is None
    elif len(bundles)==1 and isinstance(encoded,str):
        shielded_match=base64.b64decode(encoded,validate=True).hex()==bundles[0].get("serializedBundleHex")
    else:
        shielded_match=False
    expiry_match=chain.get("expiry_height") is None or int(chain["expiry_height"])==int(decoded["expiryHeight"])
    result.update({"shieldedSerializedBundleMatches":shielded_match,"expiryHeightMatches":expiry_match,
                   "verified":bool(decoded.get("ok") and result.get("inputsMatch") and result.get("outputsMatch")
                                   and shielded_match and expiry_match),
                   "warning":"Exact executed payout packet match; no proof of later private consumption or ownership."})
    return result


def investigate(args):
    args.output_dir.mkdir(parents=True,exist_ok=True)
    for directory in (args.flow_dir,args.origin_dir,args.case_dir,args.branch_dir):
        if args.output_dir.resolve()==directory.resolve() or directory.resolve() in args.output_dir.resolve().parents:
            raise ValueError("separate output required")
    manifest=json.loads((args.flow_dir/"manifest.json").read_text())
    if manifest.get("stopped") or any(manifest[key]!=digest(args.flow_dir/name) for key,name in
              (("analysisSha256","analysis.json"),("treesSha256","trees.jsonl"))):
        raise ValueError("completed hash-matching flow inputs required")
    analysis=json.loads((args.flow_dir/"analysis.json").read_text())
    trees={t["nearTransactionHash"]:t for t in (json.loads(l) for l in (args.flow_dir/"trees.jsonl").read_text().splitlines())}
    reader=ReusingReader(args)
    result={"challengeSolved":False,"modernExits":modern_exits(analysis,trees),
            "legacyExitInventory":legacy_exits(analysis,trees),"selectedLegacyRoot":args.legacy_root,
            "legacyRouteAudit":[],"modernAuditComplete":False,"warning":"Public route segments only; no commitment-to-nullifier identity."}
    result["legacyTransferInstructions"]=legacy_transfers(analysis)
    mapped={(r["nearRoot"],r["temporaryAccount"]) for r in result["legacyExitInventory"]}
    result["unmappedLegacyTransferInstructions"]=[r for r in result["legacyTransferInstructions"]
                                                if (r["nearRoot"],r["receiverAccount"]) not in mapped]
    stopped=None

    def tx(txid, receiver=None):
        detail=reader.request(f"{ZEC_API}/tx/{txid}")
        if detail.get("txid")!=txid or detail.get("isCanonical") is not True or int(detail["blockHeight"])>ANCHOR:
            raise ValueError("payout canonical identity/pre-anchor mismatch")
        raw=reader.request(f"{ZEC_API}/tx/{txid}/raw")
        packet={"hex":raw["hex"],"expectedTxid":txid,"allowV4Transparent":True,
                "blockHeight":detail["blockHeight"],"blockTime":detail["blockTime"],"isCanonical":True}
        if receiver and receiver.startswith("zcash:u1"):
            packet["unifiedAddresses"]=[receiver[len("zcash:"):]]
        decoded=json.loads(subprocess.run([str(args.decoder.resolve())],input=json.dumps(packet)+"\n",
                                          text=True,capture_output=True,check=True,timeout=30).stdout)
        if not decoded.get("ok"):
            raise CheckpointStop("raw decoder unsupported/error: "+str(decoded.get("error")))
        return {"detail":detail,"decoded":decoded}

    try:
        selected=[r for r in result["legacyExitInventory"] if r["nearRoot"]==args.legacy_root]
        if len(selected)!=1:
            raise ValueError("selected legacy root does not identify exactly one withdrawal")
        legacy=selected[0]
        if not legacy["legacyTokenBurnVerified"]:
            raise ValueError("selected legacy exit lacks successful token burn")
        addr=legacy["requestedReceiver"]
        if not addr.startswith("t"):
            raise ValueError("selected legacy audit requires a transparent receiver")
        page=reader.request(f"{ZEC_API}/address/{addr}?page=1&limit=100")
        if page.get("address")!=addr:
            raise ValueError("legacy address response identity mismatch")
        route={"withdrawal":legacy,"addressSnapshot":page,"historyComplete":(page.get("pagination") or {}).get("hasNext") is False,
               "transactions":[],"warning":"Legacy NEAR-to-Zcash association is receiver/indexer evidence, not an explicit connector transaction ID."}
        result["legacyRouteAudit"].append(route)
        eligible=[s for s in page.get("transactions") or [] if int(s["blockHeight"])<=ANCHOR
                  and int(s["blockTime"])*1000000000>=timestamp_ns(legacy["blockTime"])]
        if len(eligible)>args.max_legacy_transactions:
            raise CheckpointStop("legacy transaction cap; no address exhaustion claim")
        for summary in eligible:
            item=tx(summary["txid"])
            item["requestedReceiverOutputs"]=[o for o in item["detail"]["outputs"] if o.get("address")==addr]
            item["outputValuesVerified"]=[(int(o["vout_index"]),str(o["value"])) for o in item["requestedReceiverOutputs"]]
            raw_values={o["index"]:str(o["valueZat"]) for o in item["decoded"]["transparentOutputs"]}
            if any(raw_values.get(vout)!=amount for vout,amount in item["outputValuesVerified"]):
                raise ValueError("legacy recipient raw value/index disagreement")
            item["recipientOutputRawValuesMatch"]=True
            item["unspentAfterAnchor"]=int((page.get("pagination") or {}).get("snapshotHeight") or 0)>ANCHOR and all(
                o.get("spent") is False for o in item["requestedReceiverOutputs"]) and bool(item["requestedReceiverOutputs"])
            route["transactions"].append(item)
        print(f"legacy root={args.legacy_root} candidates={len(route['transactions'])} complete={route['historyComplete']}",flush=True)

        for exit in result["modernExits"]:
            exit["omniIndexedTransfer"]=validate_omni(reader.request(f"{OMNI_API}?origin_chain=Near&origin_nonce={exit['originNonce']}"),exit)
            print(f"modern nonce={exit['originNonce']} status={exit['omniIndexedTransfer']['status']}",flush=True)
        wanted=set()
        for exit in result["modernExits"]:
            for h in exit["omniIndexedTransfer"].get("tx_ids") or []:
                if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{40,46}",h) and h not in trees:
                    wanted.add(h)
        for offset in range(0,len(wanted),20):
            batch=sorted(wanted)[offset:offset+20]
            value=reader.request(TX_API,{"tx_hashes":batch})
            for entry in value.get("transactions") or []:
                normalized=normalize(entry)
                if normalized["nearTransactionHash"] not in batch or not normalized["treeReferencesComplete"]:
                    raise ValueError("unexpected/incomplete payout tree")
                trees[normalized["nearTransactionHash"]]=normalized
            if any(h not in trees for h in batch):
                raise CheckpointStop("missing requested payout tree")
        for exit in result["modernExits"]:
            indexed=exit["omniIndexedTransfer"]
            winning=indexed.get("utxo_winning_tx_hash")
            final=indexed.get("finalised") or {}
            if not winning:
                exit["payoutStatus"]="no-indexed-winning-payout-retain-open"
                continue
            if final.get("transaction_hash")!=winning or final.get("chain")!="Zcash":
                raise ValueError("finalised and winning payout IDs disagree")
            matches=[]
            for h in indexed.get("tx_ids") or []:
                trace=trees.get(h)
                if not trace:
                    continue
                submissions=[c for c in trace["calls"] if c["source"]=="receipt" and c["receiver"]=="omni.bridge.near"
                             and c["method"]=="submit_transfer_to_btc_connector_callback" and c["executionStatus"] in SUCCESS
                             and ((c.get("args") or {}).get("transfer_msg") or {}).get("origin_nonce")==exit["originNonce"]]
                if not submissions:
                    continue
                for p in builder_packets(trace):
                    if p.get("target_btc_address")!=exit["requestedReceiver"][len("zcash:"):] or str(p.get("amountZat"))!=exit["amountRaw"]:
                        continue
                    if any(pending["txid"]==winning for pending in pending_payouts(trace)):
                        matches.append({"nearRoot":h,"packet":p,"submission":submissions[0]})
            if len(matches)!=1:
                exit["payoutStatus"]="indexer-ID-without-unique-verified-builder"
                exit["builderCandidates"]=matches
                continue
            exit["builder"]=matches[0]
            exit["payout"]=tx(winning,exit["requestedReceiver"])
            exit["rawComparison"]=compare_complete_packet(matches[0]["packet"],exit["payout"]["decoded"])
            if not exit["rawComparison"]["verified"]:
                raise ValueError("payout serialization differs from executed builder packet")
            exit["payoutStatus"]="explicit-nonce-builder-pending-ID-raw-serialization-verified"
            print(f"verified payout nonce={exit['originNonce']} tx={winning}",flush=True)
        result["modernAuditComplete"]=True
    except (CheckpointStop,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        stopped=str(exc)
        print("checkpoint stop: "+stopped,flush=True)
    finally:
        write_rows(args.output_dir/"payout-trees.jsonl",[trees[h] for h in sorted(trees) if h not in analysis_roots(analysis)])
        dump(args.output_dir/"analysis.json",result)
        dump(args.output_dir/"manifest.json",{"createdAt":datetime.now(timezone.utc).isoformat(),"stopped":stopped,
             "challengeSolved":False,"newHttpCalls":reader.calls,"responsesUsed":reader.index,"reusedInputHashes":reader.reused,
             "flowAnalysisSha256":digest(args.flow_dir/"analysis.json"),"flowTreesSha256":digest(args.flow_dir/"trees.jsonl"),
             "decoderSha256":digest(args.decoder),"scriptSha256":digest(Path(__file__)),"analysisSha256":digest(args.output_dir/"analysis.json")})
    print(f"done: {args.output_dir/'analysis.json'} stopped={stopped}",flush=True)
    return 2 if stopped else 0


def analysis_roots(analysis):
    return {e["nearRoot"] for e in analysis["executedEvents"]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--flow-dir",type=Path,default=Path("challenge7-account-flow-data"))
    p.add_argument("--origin-dir",type=Path,default=Path("challenge7-user-origin-data"))
    p.add_argument("--case-dir",type=Path,default=Path("challenge7-account-link-data"))
    p.add_argument("--branch-dir",type=Path,default=Path("challenge7-public-branch-data"))
    p.add_argument("--output-dir",type=Path,default=Path("challenge7-account-exit-data"))
    p.add_argument("--decoder",type=Path,default=Path("decoder/target/release/note_ledger"))
    p.add_argument("--legacy-root",default=LEGACY_ROOT)
    p.add_argument("--fetch",action="store_true")
    p.add_argument("--max-legacy-transactions",type=int,default=5)
    p.add_argument("--max-http-calls",type=int,default=45)
    p.add_argument("--delay",type=float,default=10)
    a=p.parse_args()
    if min(a.max_legacy_transactions,a.max_http_calls)<1 or a.delay<1:
        p.error("positive caps and delay >=1 required")
    raise SystemExit(investigate(a))


if __name__=="__main__":
    main()
