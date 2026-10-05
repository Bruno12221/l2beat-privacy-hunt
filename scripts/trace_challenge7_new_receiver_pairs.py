#!/usr/bin/env python3
"""Bounded public-route tracing for new receiver or exact-value candidates.

Receiver/value candidates are selected offline, never labelled target spends.
Successful full execution trees, exact nonces, actual serialized builder packets,
winning transaction identity and canonical height are separate gates. Shared
relayers, quote metadata and public account addresses are not ownership proof.
"""
from __future__ import annotations
import argparse
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from analyze_challenge7_baseline import dump, write_rows, pair_indices
from audit_challenge7_connector_ids import full_tree_rpc_result
from enrich_challenge7_pending_notes import validate_envelope
from investigate_challenge7_account_links import SUCCESS, builder_packets, pending_payouts
from reconcile_challenge7_account_flows import ReusingReader, accepted_intents
from trace_challenge7_account_exits import compare_complete_packet
from trace_challenge7_public_branches import internal_swap_funding
from trace_challenge7_free_near import CheckpointStop, digest, normalize
from trace_challenge7_user_origins import TX_API, OMNI_API, ZEC_API, TRANSFERS_API, CUTOFF_NS, trusted_logs, descendants, validate_transfers, mint_deposits

TARGET=3954182
ANCHOR=3488703


def bound_builder_submission(trace,receipt,nonce,txid):
    callbacks=[c for c in trace["calls"] if c["source"]=="receipt" and c["receiver"]=="omni.bridge.near"
               and c["executionStatus"] in SUCCESS and c["method"]=="submit_transfer_to_btc_connector_callback"
               and (c.get("args",{}).get("transfer_msg") or {}).get("origin_nonce")==nonce]
    matched=[]
    for call in trace["calls"]:
        if (call["source"]!="receipt" or call["receiver"]!="omni.bridge.near" or call["executionStatus"] not in SUCCESS
                or call["method"]!="submit_transfer_to_utxo_chain_connector"):continue
        transfer=(call.get("args") or {}).get("transfer_id") or {}
        if transfer!={"origin_chain":"Near","origin_nonce":nonce}:continue
        linked=descendants(trace,call["receiptId"])
        matched_callbacks=[c for c in callbacks if c["receiptId"] in linked]
        pending=[x for x in pending_payouts(trace) if x["txid"]==txid and x["receiptId"] in descendants(trace,receipt)]
        if receipt in linked and len(matched_callbacks)==1 and len(pending)==1:
            matched.append({"submission":call,"callback":matched_callbacks[0],"pendingEvent":pending[0]})
    if len(matched)!=1:raise ValueError("unique shared-parent nonce submission and descendant pending ID required")
    return matched[0]


def receiver_pairs(old,raw,maximum_change=100000):
    notes={r["id"]:{**r,"new":False} for r in old if r.get("anchorEligibility")=="height-compatible"}
    for d in raw:
        for o in d.get("outputs") or []:
            if o.get("pool")!="ironwood" or not o.get("recovered") or int(o.get("valueZat",0))<=0:continue
            ident=f'{d["txid"]}:ironwood:{o["actionIndex"]}:{o["cmx"]}'
            if ident not in notes:notes[ident]={"id":ident,"txid":d["txid"],"valueZat":int(o["valueZat"]),"receiverBytes":[o["receiverRaw"]],"new":True}
    groups=defaultdict(list)
    for r in notes.values():
        for receiver in r["receiverBytes"]:groups[receiver].append(r)
    pairs=[]
    for receiver,rows in sorted(groups.items()):
        for i,left in enumerate(rows):
            for right in rows[i+1:]:
                total=left["valueZat"]+right["valueZat"]
                if (left["new"] or right["new"]) and TARGET<=total<=TARGET+maximum_change:
                    pairs.append({"left":left,"right":right,"receiverRaw":receiver,"inputTotalZat":total,
                                  "possibleChangeZat":total-TARGET,"targetSpendProven":False})
    return sorted(pairs,key=lambda r:(r["possibleChangeZat"],r["left"]["id"],r["right"]["id"]))


def exact_new_pairs(notes,new_txids):
    rows=[{**n,"new":n["txid"] in new_txids} for n in notes if n.get("anchorEligibility")=="height-compatible"]
    return [{"left":left,"right":right,"inputTotalZat":TARGET,"possibleChangeZat":0,"targetSpendProven":False,
             "warning":"Exact amount only; different receivers do not exclude common ownership."}
            for left,right in pair_indices(rows,TARGET,0) if left["new"] or right["new"]]


def verify_selected_note(note,decoded):
    found=[o for o in decoded.get("outputs") or [] if o.get("pool")=="ironwood" and o.get("recovered")
           and f'{decoded["txid"]}:ironwood:{o["actionIndex"]}:{o["cmx"]}'==note["id"]]
    if (len(found)!=1 or int(found[0]["valueZat"])!=note["valueZat"]
            or note["receiverBytes"]!=[found[0]["receiverRaw"]]):
        raise ValueError("selected baseline note differs from audited actual raw output")


def obtain_trees(roots,reader,ledger_dir,trees):
    """Reuse complete source-hash-checked full trees before any live batch."""
    missing=[]
    db=sqlite3.connect(f"file:{(ledger_dir/'ledger.sqlite3').resolve()}?mode=ro",uri=True)
    try:
        for h in sorted(set(roots)-trees.keys()):
            row=db.execute("SELECT data FROM roots WHERE hash=? AND done=1 AND complete=1",(h,)).fetchone()
            if row is None:missing.append(h);continue
            path=Path(json.loads(row[0])["sourceResponse"])
            saved=db.execute("SELECT sha256 FROM responses WHERE path=?",(str(path),)).fetchone()
            if saved is None:missing.append(h);continue
            if digest(path)!=saved[0]:raise ValueError("frozen full-tree source hash mismatch")
            entries=json.loads(path.read_text()).get("transactions") or []
            found=[e for e in entries if (e.get("transaction") or {}).get("hash")==h]
            if len(found)!=1:raise ValueError("exact cached full-tree root missing/duplicated")
            full_tree_rpc_result(found[0]);trees[h]=normalize(found[0])
            reader.reused[str(path.resolve())]=saved[0]
    finally:db.close()
    for offset in range(0,len(missing),20):
        batch=missing[offset:offset+20];value=reader.request(TX_API,{"tx_hashes":batch})
        if value is None:raise CheckpointStop("uncached full trees; explicit fetch required")
        returned=set()
        for entry in value.get("transactions") or []:
            full_tree_rpc_result(entry);t=normalize(entry);h=t["nearTransactionHash"]
            if h not in batch or h in returned:raise ValueError("full tree unrequested/duplicate")
            returned.add(h);trees[h]=t
        if returned!=set(batch):raise CheckpointStop("not all requested full trees returned")


def indexed_origin(indexed,trace,nonce,receiver,amount):
    found=[l for l in trusted_logs(trace,"omni.bridge.near")
           if (l["decoded"].get("InitTransferEvent") or {}).get("transfer_message",{}).get("origin_nonce")==nonce]
    if len(found)!=1:raise ValueError("unique executed origin nonce required")
    log=found[0];m=log["decoded"]["InitTransferEvent"]["transfer_message"]
    init=indexed.get("initialised") or {}
    if (init.get("transaction_hash")!=trace["nearTransactionHash"] or (init.get("details") or {}).get("receipt_id")!=log["receiptId"]
            or m.get("recipient")!="zcash:"+receiver or str(m.get("amount"))!=str(amount)
            or any(indexed.get(k)!=m.get(k) for k in ("sender","recipient"))
            or indexed.get("token_id",indexed.get("token"))!=m.get("token") or str(indexed.get("amount"))!=str(amount)):
        raise ValueError("index/executed origin identity or fields disagree")
    users=[]
    # Successful execution and accepted message hash, not relayer transaction signer.
    # An execute_intents batch may include unrelated ERC-191 solvers. Start
    # from the exact executed withdrawal, not every signer in that batch.
    # Unsupported formats for a relevant withdrawal still fail explicitly.
    candidate_accounts={item.get("account_id") for l in trusted_logs(trace,"intents.near")
                        if l["decoded"].get("standard")=="dip4" and l["decoded"].get("event")=="ft_withdraw"
                        for item in l["decoded"].get("data") or [] if item.get("account_id")
                        and item.get("receiver_id")=="omni.bridge.near" and "near:"+str(item.get("token"))==m["token"]
                        and str(item.get("amount"))==str(amount) and (item.get("msg") or {}).get("recipient")==m["recipient"]}
    for account in sorted(candidate_accounts):
        for accepted in accepted_intents(trace,account):
            if log["receiptId"] not in descendants(trace,accepted["receiptId"]):continue
            relevant=[]
            for instruction in accepted["message"].get("intents") or []:
                msg=instruction.get("msg") or {};msg=json.loads(msg) if isinstance(msg,str) else msg
                if (instruction.get("intent")=="ft_withdraw" and instruction.get("receiver_id")=="omni.bridge.near"
                        and "near:"+str(instruction.get("token"))==m["token"] and str(instruction.get("amount"))==str(amount)
                        and msg.get("recipient")==m["recipient"]):relevant.append(instruction)
            for instruction in relevant:
                logs=[l for l in trusted_logs(trace,"intents.near") if l["receiptId"]==accepted["receiptId"]]
                withdrawals=[{"receiptId":l["receiptId"],"logIndex":l["index"],**x} for l in logs
                             if l["decoded"].get("standard")=="dip4" and l["decoded"].get("event")=="ft_withdraw"
                             for x in l["decoded"].get("data") or [] if x.get("account_id")==account
                             and x.get("token")==instruction["token"] and str(x.get("amount"))==str(amount)
                             and x.get("receiver_id")=="omni.bridge.near" and (x.get("msg") or {}).get("recipient")==m["recipient"]]
                burns=[{"receiptId":l["receiptId"],"logIndex":l["index"],**x} for l in logs
                       if l["decoded"].get("standard")=="nep245" and l["decoded"].get("event")=="mt_burn"
                       for x in l["decoded"].get("data") or [] if x.get("owner_id")==account
                       and x.get("token_ids")==["nep141:"+instruction["token"]] and x.get("amounts")==[str(amount)]]
                if len(withdrawals)==1 and len(burns)==1:
                    users.append({"account":account,"acceptedInstruction":accepted,"instruction":instruction,
                                  "executedWithdrawal":withdrawals[0],"executedBurn":burns[0],"publicExecutionVerified":True})
    return {"originRoot":trace["nearTransactionHash"],"receiptId":log["receiptId"],"message":m,
            "directAcceptedIntentsUsers":users,"unresolvedUserReason":None if users else "origin-verified-but-no-direct-accepted-Intents-withdrawal; inspect-token-or-adapter-stage"}


def accepted_internal_credit(trace,event):
    """Bind an executed credit to accepted original message bytes, not a relayer.

    The contract accepted the message; its signature is not independently
    checked here. The binding does not identify an external deposit or owner.
    """
    matched=[]
    for accepted in accepted_intents(trace,event["senderAccount"]):
        if accepted["receiptId"]!=event["receiptId"]:continue
        for instruction in accepted["message"].get("intents") or []:
            tokens=instruction.get("tokens") or {}
            if (instruction.get("intent")=="transfer"
                    and instruction.get("receiver_id")==event["recipientAccount"]
                    and tokens.get(event["token"])==event["amountRaw"]):
                matched.append({"acceptedInstruction":accepted,"instruction":instruction,
                                "acceptedInstructionVerified":True})
    if len(matched)!=1:
        raise CheckpointStop("internal credit lacks unique same-receipt accepted transfer instruction")
    return matched[0]


def bound_internal_credit(trace,event):
    """Distinguish recipient-authorized swaps from sender-authored transfers."""
    matches=[]
    for accepted in accepted_intents(trace,event["recipientAccount"]):
        if accepted["receiptId"]!=event["receiptId"]:continue
        for instruction in accepted["message"].get("intents") or []:
            if (instruction.get("intent")=="token_diff"
                    and (instruction.get("diff") or {}).get(event["token"])==event["amountRaw"]):
                matches.append({"acceptedRecipientInstruction":accepted,"recipientInstruction":instruction})
    if len(matches)>1:raise CheckpointStop("ambiguous recipient-authorized swap credit")
    if matches:
        return {**matches[0],"acceptedInstructionVerified":False,"recipientSwapInstructionVerified":True,
                "creditClassification":"accepted-recipient-token-diff-and-executed-credit",
                "senderInstructionHashVerified":False,
                "warning":"Atomic exchange credit; sender is an executed liquidity counterparty, not the recipient's original external funder."}
    return {**accepted_internal_credit(trace,event),"recipientSwapInstructionVerified":False,
            "creditClassification":"accepted-sender-transfer-and-executed-credit"}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw-dir",type=Path,default=Path("challenge7-pending-raw-data"))
    p.add_argument("--old-notes",type=Path,default=Path("challenge7-decoded-baseline-v3-data/decoded-notes.jsonl"))
    p.add_argument("--requests",type=Path,default=Path("challenge7-free-raw-rescue-data/combined-raw-withdrawals.jsonl"))
    p.add_argument("--output-dir",type=Path,default=Path("challenge7-new-receiver-pairs-data"))
    p.add_argument("--fetch",action="store_true")
    p.add_argument("--max-http-calls",type=int,default=40)
    p.add_argument("--delay",type=float,default=3)
    p.add_argument("--selection",choices=["same-receiver","new-exact-pairs"],default="same-receiver")
    p.add_argument("--baseline-dir",type=Path,default=Path("challenge7-decoded-baseline-v4-data"))
    p.add_argument("--old-raw-dir",type=Path,default=Path("challenge7-batch-note-data"))
    p.add_argument("--pending-audit-dir",type=Path,default=Path("challenge7-connector-id-audit-v2-data"))
    p.add_argument("--ledger-dir",type=Path,default=Path("challenge7-withdrawal-ledger-data"))
    p.add_argument("--include-close-new-singles",type=int,default=0)
    a=p.parse_args()
    if a.delay<1 or not 0<=a.max_http_calls<=40 or not 0<=a.include_close_new_singles<=2:raise ValueError("capped paced scope required")
    if a.selection!="new-exact-pairs" and a.include_close_new_singles:raise ValueError("single selection requires declared expanded baseline scope")
    if a.selection=="new-exact-pairs" and a.output_dir==Path("challenge7-new-receiver-pairs-data"):
        raise ValueError("new exact-pair run requires a separate output directory")
    a.origin_dir=Path("challenge7-user-origin-data");a.case_dir=Path("challenge7-account-link-data");a.branch_dir=Path("challenge7-public-branch-data")
    a.output_dir.mkdir(parents=True,exist_ok=True)
    path=a.raw_dir/"decoded-transactions.jsonl";m=json.loads((a.raw_dir/"offline-audit.json").read_text())
    if not m["allScopedTransactionsDecoded"] or not m["offlineFullDecodedReplayMatches"] or m["ledgerSha256"]!=digest(path):raise ValueError("fully replayed hash-matching raw input required")
    raw=[json.loads(l) for l in path.open()];by_id={r["txid"]:r for r in raw}
    selection_hashes={};singles=[];notes_by_txid={}
    if a.selection=="same-receiver":
        pairs=receiver_pairs(map(json.loads,a.old_notes.open()),raw)
        wanted=sorted({r[side]["txid"] for r in pairs for side in ("left","right") if r[side]["new"]})
        proofs={h:d["pendingRequestProvenance"] for h,d in by_id.items()}
    else:
        old_path=a.old_raw_dir/"decoded-transactions.jsonl";old_audit=json.loads((a.old_raw_dir/"offline-audit.json").read_text())
        if (not old_audit["allScopedTransactionsDecoded"] or not old_audit["offlineFullDecodedReplayMatches"]
                or old_audit["ledgerSha256"]!=digest(old_path)):raise ValueError("old raw ledger replay/hash mismatch")
        old=[json.loads(l) for l in old_path.open()]
        if set(by_id)&{r["txid"] for r in old}:raise ValueError("overlapping frozen raw scopes")
        new_txids=set(by_id);by_id.update({r["txid"]:r for r in old})
        baseline_path=a.baseline_dir/"decoded-notes.jsonl";notes=list(map(json.loads,baseline_path.open()))
        pairs=exact_new_pairs(notes,new_txids)
        singles=sorted([{**n,"new":True,"possibleChangeZat":n["valueZat"]-TARGET,"targetSpendProven":False}
                       for n in notes if n["txid"] in new_txids and n.get("anchorEligibility")=="height-compatible"
                       and TARGET<=n["valueZat"]<=TARGET+100000],key=lambda n:(n["possibleChangeZat"],n["id"]))[:a.include_close_new_singles]
        selected=[r[side] for r in pairs for side in ("left","right")]+singles
        for note in selected:
            verify_selected_note(note,by_id[note["txid"]]);notes_by_txid[note["txid"]]=note
        wanted=sorted(notes_by_txid)
        audit=json.loads((a.pending_audit_dir/"manifest.json").read_text());proof_path=a.pending_audit_dir/"pending-ids.jsonl"
        if audit["pendingIdsSha256"]!=digest(proof_path) or audit["requestsSha256"]!=digest(a.requests):raise ValueError("pending audit/requests hash mismatch")
        proofs={}
        for proof in map(json.loads,proof_path.open()):
            if proof["txid"] not in wanted:continue
            if proof["txid"] in proofs:raise ValueError("selected pending ID has multiple requests; explicit disambiguation required")
            proofs[proof["txid"]]=proof
        if set(proofs)!=set(wanted):raise ValueError("selected actual payout lacks exact pending-ID request evidence")
        selection_hashes={"baselineNotesSha256":digest(baseline_path),"baselineManifestSha256":digest(a.baseline_dir/"manifest.json"),
                          "oldRawLedgerSha256":digest(old_path),"pendingIdsSha256":digest(proof_path)}
    if len(wanted)>20:raise ValueError("more than 20 new transactions; choose declared smaller scope")
    reqs={(r["nearTransactionHash"],r["receiptId"]):r for r in map(json.loads,a.requests.open())}
    reader=ReusingReader(a);reader.old_dirs += [Path("challenge7-pending-coverage-probe-data"),Path("challenge7-pending-enriched-data")]
    cases=[];trees={};histories=[];deposits=[];credits=[];stopped="unexpected failure before completion"
    try:
        for h in wanted:
            d=by_id[h];provenance=proofs[h]
            request=reqs[(provenance["nearRoot"],provenance["listedReceiptId"])]
            nonce=int(request["transferOriginNonce"])
            value=reader.request(f"{OMNI_API}?origin_chain=Near&origin_nonce={nonce}")
            if value is None:raise CheckpointStop("uncached exact indexed nonce; explicit fetch required")
            matched=[x for x in value.get("transfers") or [] if x.get("transfer_id")=={"type":"nonce","chain":"Near","nonce":nonce}]
            if len(matched)!=1:raise CheckpointStop("no unique exact indexed nonce")
            indexed=matched[0];final=indexed.get("finalised") or {}
            if indexed.get("utxo_winning_tx_hash")!=h or final.get("transaction_hash")!=h or final.get("chain")!="Zcash":raise CheckpointStop("pending ID is not exact finalised winning Zcash ID")
            if indexed.get("recipient")!="zcash:"+request["targetAddress"]:raise ValueError("index/request receiver disagreement")
            metadata_source=notes_by_txid.get(h,{}).get("canonicalMetadataSource")
            if metadata_source:
                source_path=Path(metadata_source["path"])
                if digest(source_path)!=metadata_source["sha256"]:raise ValueError("selected original canonical metadata hash mismatch")
                envelope=json.loads(source_path.read_text())
                if envelope.get("httpStatus")!=200:raise ValueError("selected canonical metadata HTTP status mismatch")
                detail=validate_envelope(envelope,f"{ZEC_API}/tx/{h}");reader.reused[str(source_path.resolve())]=digest(source_path)
            else:detail=reader.request(f"{ZEC_API}/tx/{h}")
            if detail is None:raise CheckpointStop("uncached canonical payout metadata; explicit fetch required")
            if detail.get("txid")!=h or detail.get("isCanonical") is not True or int(detail["blockHeight"])>ANCHOR:raise CheckpointStop("candidate not canonical/pre-anchor")
            cases.append({"txid":h,"request":request,"indexedTransfer":indexed,"metadata":detail,"publicPayoutVerified":False})
            print(f"candidate metadata/nonces={len(cases)}/{len(wanted)}",flush=True)
        roots=sorted({c["request"]["nearTransactionHash"] for c in cases}|{c["indexedTransfer"]["initialised"]["transaction_hash"] for c in cases})
        if len(roots)>20:raise ValueError("full-tree batch scope exceeded")
        if roots and a.selection=="new-exact-pairs":obtain_trees(roots,reader,a.ledger_dir,trees)
        elif roots:
            value=reader.request(TX_API,{"tx_hashes":roots})
            for entry in value.get("transactions") or []:
                t=normalize(entry);h=t["nearTransactionHash"]
                if h not in roots or h in trees or not t["treeReferencesComplete"]:raise ValueError("unrequested/duplicate/incomplete full tree")
                trees[h]=t
            if set(trees)!=set(roots):raise CheckpointStop("not all requested full trees returned")
        for case in cases:
            h=case["txid"];request=case["request"];nonce=int(request["transferOriginNonce"]);t=trees[request["nearTransactionHash"]]
            packets=[packet for packet in builder_packets(t) if packet["receiptId"]==request["receiptId"]]
            if len(packets)!=1:raise ValueError("unique exact executed listed builder receipt required")
            packet=packets[0]
            case["submissionBinding"]=bound_builder_submission(t,request["receiptId"],nonce,h)
            comparison=compare_complete_packet(packet,by_id[h])
            if not comparison["verified"]:raise ValueError("actual raw serialization differs from executed builder packet")
            if str(packet["amountZat"])!=str(case["indexedTransfer"]["amount"]):raise ValueError("actual indexed/builder amount differs")
            origin=trees[case["indexedTransfer"]["initialised"]["transaction_hash"]]
            case["builderPacket"]=packet;case["rawComparison"]=comparison
            case["origin"]=indexed_origin(case["indexedTransfer"],origin,nonce,request["targetAddress"],packet["amountZat"])
            case["publicPayoutVerified"]=True
            print(f'public origin={nonce} directAcceptedUsers={len(case["origin"]["directAcceptedIntentsUsers"])}',flush=True)
        accounts=sorted({u["account"] for c in cases for u in c["origin"]["directAcceptedIntentsUsers"]})
        for account in accounts:
            spec={"account_id":account,"direction":"receiver","desc":False,"limit":100,"to_timestamp_ms":CUTOFF_NS//1000000}
            value=reader.request(TRANSFERS_API,spec)
            if value is None:raise CheckpointStop("uncached initiating-account incoming history; explicit fetch required")
            rows,cursor,_=validate_transfers(value,spec,None)
            histories.append({"account":account,"spec":spec,"rows":rows,"complete":cursor is None,"resumeToken":cursor,
                              "warning":"All indexed incoming assets in one declared page; no exclusive fungible allocation to a withdrawal."})
            print(f"incoming account={account[:12]} rows={len(rows)} complete={cursor is None}",flush=True)
        deposit_candidates=[(history["account"],r) for history in histories for r in history["rows"]
                            if r["asset_id"].startswith("nep245:intents.near:") and r.get("other_account_id") is None]
        if any(not r.get("transaction_id") for _,r in deposit_candidates):raise CheckpointStop("deposit root IDs missing; receipt lookup needed")
        funding_rows=[(history["account"],r) for history in histories for r in history["rows"] if r["asset_id"].startswith("nep245:intents.near:")]
        extra_roots=sorted({r["transaction_id"] for _,r in funding_rows}-trees.keys())
        if len(extra_roots)>40:raise CheckpointStop("deposit-tree scope above 40; larger run required")
        if a.selection=="new-exact-pairs":
            obtain_trees(extra_roots,reader,a.ledger_dir,trees);extra_roots=[]
        for offset in range(0,len(extra_roots),20):
            batch=extra_roots[offset:offset+20]
            entries=reader.request(TX_API,{"tx_hashes":batch}).get("transactions") or []
            returned=set()
            for entry in entries:
                t=normalize(entry);h=t["nearTransactionHash"]
                if h not in batch or h in returned or not t["treeReferencesComplete"]:raise ValueError("deposit tree unrequested/duplicate/incomplete")
                returned.add(h);trees[h]=t
            if set(batch)!=returned:raise CheckpointStop("deposit tree missing from batch")
        for account in accounts:
            roots={r["transaction_id"] for owner,r in deposit_candidates if owner==account}
            for h in sorted(roots):deposits.extend(mint_deposits(trees[h],account))
        by_mint={(m["account"],m["receiptId"],m["logIndex"],"nep245:intents.near:"+m["token"],m["amountRaw"]):m for m in deposits}
        unreconciled=[{"account":account,"indexedRow":r} for account,r in deposit_candidates
                      if (account,r["receipt_id"],r["log_index"],r["asset_id"],str(int(r["amount"]))) not in by_mint]
        if unreconciled:
            write_rows(a.output_dir/"unreconciled-deposits.jsonl",unreconciled)
            raise CheckpointStop("indexed deposit candidates do not all reconcile to actual successful mint events")
        for account,row in funding_rows:
            if row.get("other_account_id") is None:continue
            token=row["asset_id"][len("nep245:intents.near:"):]
            events=internal_swap_funding(trees[row["transaction_id"]],row["other_account_id"],account,token,row["amount"])
            events=[e for e in events if e["receiptId"]==row["receipt_id"] and e["logIndex"]==row["log_index"]]
            if len(events)!=1:raise CheckpointStop("incoming internal credit lacks unique matching successful indexed event")
            signed=bound_internal_credit(trees[row["transaction_id"]],events[0])
            logs=trusted_logs(trees[row["transaction_id"]],"intents.near")
            accepted_accounts=sorted({item["account_id"] for l in logs
                                     if l["decoded"].get("standard")=="dip4" and l["decoded"].get("event")=="intents_executed"
                                     for item in l["decoded"].get("data") or []})
            executed_assets=sorted({token for l in logs if l["decoded"].get("standard")=="nep245"
                                   for item in l["decoded"].get("data") or [] for token in item.get("token_ids") or []})
            credits.append({"account":account,"indexedRow":row,"executedEvent":events[0],**signed,
                            "observedAcceptedAccounts":accepted_accounts,"observedExecutedAssets":executed_assets,
                            "warning":"Exact public internal credit, not an EVM deposit or exclusive solver-fund allocation."})
        stopped=None
    except CheckpointStop as exc:stopped=str(exc)
    finally:
        write_rows(a.output_dir/"pairs.jsonl",pairs);write_rows(a.output_dir/"single-hypotheses.jsonl",singles)
        write_rows(a.output_dir/"cases.jsonl",cases);write_rows(a.output_dir/"trees.jsonl",trees.values())
        write_rows(a.output_dir/"incoming-histories.jsonl",histories);write_rows(a.output_dir/"mint-deposits.jsonl",deposits)
        write_rows(a.output_dir/"internal-credits.jsonl",credits)
        dump(a.output_dir/"manifest.json",{"challengeSolved":False,"targetPrivateSpendLink":False,"stopped":stopped,
             "selection":a.selection,"selectionInputHashes":selection_hashes,"selectedSingles":len(singles),
             "selectedPairs":len(pairs),"selectedTransactions":len(wanted),"publiclyVerifiedPayouts":sum(c["publicPayoutVerified"] for c in cases),
             "newHttpCalls":reader.calls,"responsesUsed":reader.index,"reusedSources":reader.reused,
             "rawLedgerSha256":digest(path),"oldNotesSha256":digest(a.old_notes),"requestsSha256":digest(a.requests),
             "casesSha256":digest(a.output_dir/"cases.jsonl"),"treesSha256":digest(a.output_dir/"trees.jsonl"),"scriptSha256":digest(Path(__file__)),
             "incomingHistoriesSha256":digest(a.output_dir/"incoming-histories.jsonl"),"mintDepositsSha256":digest(a.output_dir/"mint-deposits.jsonl"),
             "incomingHistoriesComplete":bool(histories) and all(h["complete"] for h in histories),"executedMintDeposits":len(deposits),
             "executedInternalCredits":len(credits),"internalCreditsSha256":digest(a.output_dir/"internal-credits.jsonl"),
             "acceptedInternalCredits":sum(c["acceptedInstructionVerified"] for c in credits),
             "acceptedRecipientSwapCredits":sum(c["recipientSwapInstructionVerified"] for c in credits),
             "internalCreditSenders":sorted({c["executedEvent"]["senderAccount"] for c in credits}),
             "internalCreditAcceptedKeys":sorted({c["acceptedInstruction"]["publicKey"] for c in credits if c["acceptedInstructionVerified"]}),
             "warning":"Declared small receiver/amount candidate scope, not an exhaustive search, common ownership proof, or target consumed-note identification."})
    print(f"{'checkpoint' if stopped else 'done'}: selection={a.selection} payouts={sum(c['publicPayoutVerified'] for c in cases)}/{len(wanted)} credits={len(credits)} deposits={len(deposits)} newHTTP={reader.calls} stopped={stopped}",flush=True)
    return 2 if stopped else 0


if __name__=="__main__":raise SystemExit(main())
