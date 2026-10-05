#!/usr/bin/env python3
"""Trace exact Omni nonces to users and enumerate public incoming funding.

Cache-only by default. Explicit --fetch enables capped, paced public reads.
No keys, signing, paid services, or writes to previous collector outputs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from investigate_challenge7_account_links import Evidence, SUCCESS, ZEC_API, load_trace
from trace_challenge7_free_near import CheckpointStop, digest, normalize, ns_iso

TX_API = "https://tx.main.fastnear.com/v0/transactions"
ACCOUNT_API = "https://tx.main.fastnear.com/v0/account"
TRANSFERS_API = "https://transfers.main.fastnear.com/v0/transfers"
OMNI_API = "https://mainnet.api.bridge.nearone.org/api/v4/transfers/transfer"
SHARED = "668833e28002698e833f9734870ea09c169eaf40dfbb8151a18c56dcc5128f1f"
CUTOFF_NS = 1789812071000000000


def trusted_logs(trace, receiver):
    status = {o["receiptId"]: o["executionStatus"] for o in trace["outcomes"]}
    return [l for l in trace["logs"] if l["receiver"] == receiver
            and status.get(l["receiptId"]) in SUCCESS and isinstance(l.get("decoded"), dict)]


def descendants(trace, receipt):
    children = {o["receiptId"]: o.get("childReceiptIds") or [] for o in trace["outcomes"]}
    reached, queue = set(), [receipt]
    while queue:
        rid = queue.pop()
        if rid not in reached:
            reached.add(rid)
            queue.extend(children.get(rid, []))
    return reached


def exact_origin(trace, connector):
    """Require trusted nonce event, accepted signed instruction, event and burn.

    The public-key signature is not independently cryptographically verified:
    successful contract execution is the evidence of instruction acceptance.
    """
    request = connector["selectedRequest"]
    nonce, amount = int(request["transferOriginNonce"]), str(int(connector["actualBuilderPacket"]["amountZat"]))
    recipient, token = "zcash:" + request["targetAddress"], "nzec.bridge.near"
    events = []
    for log in trusted_logs(trace, "omni.bridge.near"):
        msg = (log["decoded"].get("InitTransferEvent") or {}).get("transfer_message") or {}
        if (msg.get("origin_nonce") == nonce and msg.get("token") == "near:" + token
                and str(msg.get("amount")) == amount and msg.get("recipient") == recipient
                and msg.get("sender") == "near:intents.near"):
            events.append({"receiptId": log["receiptId"], "logIndex": log["index"], "message": msg})
    result = []
    for call in trace["calls"]:
        if (call["source"] != "receipt" or call["receiver"] != "intents.near"
                or call["method"] != "execute_intents" or call["executionStatus"] not in SUCCESS):
            continue
        logs = [l for l in trusted_logs(trace, "intents.near") if l["receiptId"] == call["receiptId"]]
        for signed in (call.get("args") or {}).get("signed") or []:
            message = (signed.get("payload") or {}).get("message") or {}
            account = message.get("signer_id")
            for instruction in message.get("intents") or []:
                if (instruction.get("intent") != "ft_withdraw" or instruction.get("token") != token
                        or instruction.get("receiver_id") != "omni.bridge.near"
                        or str(instruction.get("amount")) != amount
                        or (instruction.get("msg") or {}).get("recipient") != recipient):
                    continue
                executed, burned = [], []
                for log in logs:
                    event = log["decoded"]
                    for item in event.get("data") or []:
                        if (event.get("standard") == "dip4" and event.get("event") == "ft_withdraw"
                                and item.get("account_id") == account and item.get("token") == token
                                and item.get("receiver_id") == "omni.bridge.near"
                                and str(item.get("amount")) == amount
                                and (item.get("msg") or {}).get("recipient") == recipient):
                            executed.append({"receiptId": log["receiptId"], "logIndex": log["index"], **item})
                        if (event.get("standard") == "nep245" and event.get("event") == "mt_burn"
                                and item.get("owner_id") == account
                                and item.get("token_ids") == ["nep141:" + token]
                                and item.get("amounts") == [amount]):
                            burned.append({"receiptId": log["receiptId"], "logIndex": log["index"], **item})
                downstream = descendants(trace, call["receiptId"])
                linked = [e for e in events if e["receiptId"] in downstream]
                if executed and burned and len(linked) == 1:
                    result.append({"nearRoot": trace["nearTransactionHash"], "blockTime": call["blockTime"],
                                   "executedReceipt": call["receiptId"], "intentsAccount": account,
                                   "publicKey": signed.get("public_key"), "standard": signed.get("standard"),
                                   "originNonce": nonce, "amountRaw": amount, "token": token,
                                   "requestedReceiver": request["targetAddress"], "instruction": instruction,
                                   "executedWithdrawalEvents": executed, "burnEvents": burned,
                                   "initTransferEvent": linked[0], "payoutTxid": connector["payoutTxid"],
                                   "builderRoot": connector["nearRoot"],
                                   "warning": "Verified execution-to-public-payout path, not a target private-spend or exclusive external-funder proof."})
    return result


def validate_transfers(value, spec, previous_token, previous_order=None):
    if not isinstance(value, dict) or not isinstance(value.get("transfers"), list):
        raise ValueError("unexpected transfers response shape")
    rows = value["transfers"]
    for row in rows:
        clock = int(row["block_timestamp"])
        if row.get("account_id") != spec["account_id"] or int(row["amount"]) <= 0:
            raise ValueError("incoming transfer account/direction mismatch")
        if clock >= int(spec["to_timestamp_ms"]) * 1_000_000:
            raise ValueError("incoming transfer outside cutoff")
        if spec.get("ignore_system") and row.get("other_account_id") == "system":
            raise ValueError("system row outside scope")
        if spec.get("asset_id") and row.get("asset_id") != spec["asset_id"]:
            raise ValueError("asset mismatch")
    order = [(int(r["block_timestamp"]), int(r["transfer_index"])) for r in rows]
    if order != sorted(order) or (order and previous_order is not None and order[0] <= previous_order):
        raise ValueError("incoming transfer order/continuation mismatch")
    token = value.get("resume_token")
    if token is not None and (token == previous_token or not rows):
        raise ValueError("nonadvancing transfers cursor")
    return rows, token, order[-1] if order else previous_order


def mint_deposits(trace, account):
    """Actual successful mint and same-receipt callback, not an indexer label.

    Explicit external IDs require trusted bridge calls in the callback's receipt
    ancestry. Refund mints are preserved separately, never treated as new funds.
    """
    result = []
    clocks = {c["receiptId"]: c for c in trace["calls"] if c["source"] == "receipt"}
    for log in trusted_logs(trace, "intents.near"):
        event = log["decoded"]
        if event.get("standard") != "nep245" or event.get("event") != "mt_mint":
            continue
        for item in event.get("data") or []:
            if item.get("owner_id") != account:
                continue
            tokens, amounts = item.get("token_ids") or [], item.get("amounts") or []
            if len(tokens) != len(amounts):
                raise ValueError("mint token/amount array lengths disagree")
            for token, amount in zip(tokens, amounts):
                if not token.startswith("nep141:"):
                    continue
                contract = token[len("nep141:"):]
                callbacks = [c for c in trace["calls"] if c["source"] == "receipt"
                             and c["receiptId"] == log["receiptId"] and c["receiver"] == "intents.near"
                             and c["method"] == "ft_on_transfer" and c["predecessor"] == contract
                             and c["executionStatus"] in SUCCESS
                             and str((c.get("args") or {}).get("amount")) == str(amount)]
                row = {"nearRoot": trace["nearTransactionHash"], "receiptId": log["receiptId"],
                       "logIndex": log["index"], "account": account, "token": token,
                       "amountRaw": str(int(amount)), "blockTime": clocks.get(log["receiptId"], {}).get("blockTime"),
                       "blockTimestampNs": clocks.get(log["receiptId"], {}).get("blockTimestampNs"),
                       "sameReceiptCallbacks": callbacks, "externalDeposits": [],
                       "classification": "refund-or-unclassified-mint" if not callbacks else "direct-token-deposit"}
                if row["blockTimestampNs"] is None or int(row["blockTimestampNs"]) >= CUTOFF_NS:
                    continue
                for call in trace["calls"]:
                    args = call.get("args") or {}
                    if (not callbacks or call["source"] != "receipt" or call["receiver"] != "omft.near"
                            or call["predecessor"] != "bridge-mng.near" or call["method"] != "ft_deposit"
                            or call["executionStatus"] not in SUCCESS or args.get("owner_id") != "intents.near"
                            or args.get("token", "") + ".omft.near" != contract
                            or str(args.get("amount")) != str(amount)
                            or (args.get("msg") or {}).get("receiver_id") != account
                            or log["receiptId"] not in descendants(trace, call["receiptId"])):
                        continue
                    memo = args.get("memo")
                    if isinstance(memo, dict) and memo.get("txHash"):
                        row["externalDeposits"].append({"receiptId": call["receiptId"], "blockTime": call["blockTime"],
                                                         "token": args["token"], "amountRaw": str(int(amount)), "memo": memo})
                if row["externalDeposits"]:
                    row["classification"] = "explicit-external-bridge-deposit-and-executed-mint"
                result.append(row)
    return result


def connector_deposit_links(trace, mint_receipt, recipient, amount, intents_account=None):
    """Trusted verifier callback + descendant token mint, retaining gross/net.

    This identifies public Zcash deposit outpoints, not their private funding.
    Public verifier callers/relayers are not treated as user funding addresses.
    """
    matches = []
    for verify in trace["calls"]:
        if (verify["source"] != "receipt" or verify["receiver"] != "zcash-connector.bridge.near"
                or verify["method"] not in ("verify_deposit", "verify_deposit_v2")
                or verify["executionStatus"] not in SUCCESS):
            continue
        va = verify.get("args") or {}
        if (va.get("deposit_msg") or {}).get("recipient_id") != recipient:
            continue
        reached = descendants(trace, verify["receiptId"])
        if mint_receipt not in reached:
            continue
        for call in trace["calls"]:
            a = call.get("args") or {}
            info = a.get("pending_utxo_info") or {}
            utxo = info.get("utxo") or {}
            if (call["source"] != "receipt" or call["receiver"] != "zcash-connector.bridge.near"
                    or call["predecessor"] != "zcash-connector.bridge.near"
                    or call["method"] not in ("verify_deposit_callback", "verify_safe_deposit_callback")
                    or call["executionStatus"] not in SUCCESS or call["receiptId"] not in reached
                    or mint_receipt not in descendants(trace, call["receiptId"])
                    or a.get("recipient_id") != recipient or str(a.get("mint_amount")) != str(amount)
                    or not info.get("tx_id") or int(utxo.get("vout", -1)) != int(va.get("vout", -2))):
                continue
            if intents_account is not None and (a.get("msg") or {}).get("receiver_id") != intents_account:
                continue
            if intents_account is None and not any(m["source"] == "receipt" and m["receiptId"] == mint_receipt
                                                   and m["receiver"] == "nzec.bridge.near" and m["predecessor"] == "zcash-connector.bridge.near"
                                                   and m["method"] == "mint" and m["executionStatus"] in SUCCESS
                                                   and (m.get("args") or {}).get("mint_account_id") == recipient
                                                   and str((m.get("args") or {}).get("mint_amount")) == str(amount)
                                                   for m in trace["calls"]):
                continue
            encoded = va.get("tx_bytes")
            raw = (base64.b64decode(encoded, validate=True).hex() if isinstance(encoded, str)
                   else bytes(encoded).hex() if isinstance(encoded, list)
                   else bytes(utxo.get("tx_bytes") or []).hex())
            if not raw:
                raise ValueError("connector deposit missing original transaction bytes")
            key = f"{info['tx_id']}@{int(utxo['vout'])}"
            if info.get("utxo_storage_key") != key:
                raise ValueError("connector callback outpoint/storage-key disagreement")
            proof_hash = va.get("tx_block_blockhash") or (va.get("proof") or {}).get("tx_block_blockhash")
            matches.append({"nearRoot": trace["nearTransactionHash"], "verifyReceipt": verify["receiptId"],
                            "callbackReceipt": call["receiptId"], "mintReceipt": mint_receipt,
                            "recipient": recipient, "intentsAccount": intents_account,
                            "zecTxid": info["tx_id"], "vout": int(utxo["vout"]),
                            "grossDepositZat": str(int(utxo["balance"])), "netMintZat": str(int(amount)),
                            "protocolFeeZat": str(int(a.get("protocol_fee") or 0)),
                            "relayerFeeZat": str(int(a.get("relayer_fee") or 0)),
                            "proofBlockHash": proof_hash, "rawHex": raw,
                            "warning": "Accepted connector deposit execution and exact outpoint; private funding and ownership are not established."})
    return matches


class Reader(Evidence):
    def request(self, url, body=None):
        value = super().request(url, body)
        if value is None:
            raise CheckpointStop("missing cached response; --fetch required: " + url)
        path = Path(self.index[-1]["path"])
        envelope = json.loads(path.read_text())
        if envelope["url"] != url or envelope.get("request") != body:
            raise ValueError("cached response request mismatch")
        if hashlib.sha256(envelope["rawUtf8"].encode()).hexdigest() != envelope["responseBytesSha256"]:
            raise ValueError("original cached response hash mismatch")
        if json.loads(envelope["rawUtf8"]) != value:
            raise ValueError("cached parsed payload differs from original bytes")
        return value


def investigate(args):
    out = args.output_dir
    for p in (args.case_dir, args.branch_dir, args.ledger_dir):
        if out.resolve() == p.resolve() or p.resolve() in out.resolve().parents:
            raise ValueError("output must be separate from frozen inputs")
    out.mkdir(parents=True, exist_ok=True)
    reader = Reader(out, args.fetch, args.max_http_calls, args.delay)
    db = sqlite3.connect("file:" + str((args.ledger_dir / "ledger.sqlite3").resolve()) + "?mode=ro", uri=True)
    branch = json.loads((args.branch_dir / "analysis.json").read_text())
    trees, used, reused, incoming, stopped = {}, {}, {}, [], "unexpected failure before completion"
    result = {"challengeSolved": False, "targetPrivateSpendLink": False,
              "connectorOrigins": [], "mintDeposits": [], "incomingInventory": {}}
    # Reuse normalized snapshots and original new response envelopes; never
    # change the original completed datasets or silently refresh their trees.
    for path in (args.case_dir / "funding-traces.jsonl", args.branch_dir / "bridge-deposit-traces.jsonl"):
        if path.exists():
            reused[str(path.resolve())] = digest(path)
            for line in path.read_text().splitlines():
                tree = json.loads(line)
                trees[tree["nearTransactionHash"]] = tree
    for path in sorted((out / "http-responses").glob("*.json")):
        envelope = json.loads(path.read_text())
        if envelope["url"] != TX_API:
            continue
        if hashlib.sha256(envelope["rawUtf8"].encode()).hexdigest() != envelope["responseBytesSha256"]:
            raise ValueError("new raw-tree response hash mismatch")
        if json.loads(envelope["rawUtf8"]) != envelope["response"]:
            raise ValueError("new parsed tree differs from original response bytes")
        for entry in envelope["response"].get("transactions") or []:
            trees[entry["transaction"]["hash"]] = normalize(entry)
            reused[str(path.resolve())] = digest(path)

    def obtain(hashes):
        missing = []
        for h in sorted(set(hashes)):
            if h not in trees:
                trees[h] = load_trace(db, h, {})
                if trees[h] is not None:
                    meta = json.loads(db.execute("SELECT data FROM roots WHERE hash=?", (h,)).fetchone()[0])
                    source = Path(meta["sourceResponse"])
                    reused[str(source.resolve())] = digest(source)
            if trees.get(h) is None:
                missing.append(h)
        if len(missing) > args.max_new_roots:
            raise CheckpointStop(f"new root limit: {len(missing)} required > {args.max_new_roots}; no partial funding claim")
        for offset in range(0, len(missing), 20):
            batch = missing[offset:offset + 20]
            value = reader.request(TX_API, {"tx_hashes": batch})
            for entry in value.get("transactions") or []:
                h = entry["transaction"]["hash"]
                if h not in batch:
                    raise ValueError("unrequested root returned")
                trees[h] = normalize(entry)
            if any(trees.get(h) is None for h in batch):
                raise CheckpointStop("missing root(s) in batch; retained response, no guessed linkage")
            print(f"funding roots new={min(offset+20,len(missing))}/{len(missing)}", flush=True)
        for h in sorted(set(hashes)):
            if not trees[h]["treeReferencesComplete"]:
                raise CheckpointStop("incomplete referenced receipt tree: " + h)
            used[h] = trees[h]
        return [trees[h] for h in sorted(set(hashes))]

    try:
        for connector in branch["olderConnectorPayoutLinks"]:
            if not connector["explicitPendingIdMatches"] or not connector["rawComparison"]["verified"]:
                raise ValueError("prior public payout verification missing")
            nonce = int(connector["selectedRequest"]["transferOriginNonce"])
            value = reader.request(f"{OMNI_API}?origin_chain=Near&origin_nonce={nonce}")
            candidates = [t for t in value.get("transfers") or [] if t.get("transfer_id") == {"type": "nonce", "chain": "Near", "nonce": nonce}
                          and t.get("utxo_winning_tx_hash") == connector["payoutTxid"]]
            if len(candidates) != 1:
                raise ValueError("Omni lookup ambiguous or payout mismatch")
            indexed = candidates[0]
            init = indexed["initialised"]
            if init.get("chain") != "Near":
                raise ValueError("unexpected initialisation chain")
            trace = obtain([init["transaction_hash"]])[0]
            matches = exact_origin(trace, connector)
            if len(matches) != 1 or matches[0]["initTransferEvent"]["receiptId"] != init["details"]["receipt_id"]:
                raise ValueError("origin nonce/withdrawal/burn link missing or ambiguous")
            matches[0]["omniIndexedTransfer"] = indexed
            result["connectorOrigins"].extend(matches)
            print(f"origin nonce={nonce} user={matches[0]['intentsAccount']} time={matches[0]['blockTime']}", flush=True)

        if {r["intentsAccount"] for r in result["connectorOrigins"]} != {SHARED}:
            raise CheckpointStop("origins are not the assumed shared account; stop before widening account scope")
        cases = [json.loads(s) for s in (args.case_dir/"cases.jsonl").read_text().splitlines() if s]
        case_d = next(c for c in cases if c["caseNumber"] == 4)
        tokens = sorted({r["originAsset"] for r in case_d["internalIntentsAccountRoutes"]}
                        | {"nep141:zec.omft.near", "nep141:nzec.bridge.near"})
        reused[str((args.case_dir/"cases.jsonl").resolve())] = digest(args.case_dir/"cases.jsonl")
        # Exact assets used in the known conversions, plus both ZEC wrappers.
        # All amounts and all available earlier dates are retained. This is NOT
        # every token the account ever held. Do not use ignore_system: the live
        # API also drops null-counterparty mints with that option.
        seen = set()
        inventory = {"scopes": [], "listingComplete": False, "tokenIds": tokens,
                     "warning": "Complete indexed incoming histories only for these declared assets. Other assets, opening balances, outgoing allocations and indexer completeness remain unknown."}
        result["incomingInventory"] = inventory
        for asset in tokens:
            spec = {"account_id": SHARED, "asset_id": "nep245:intents.near:"+asset,
                    "desc": False, "to_timestamp_ms": CUTOFF_NS // 1_000_000,
                    "limit": 100, "direction": "receiver"}
            token, order = None, None
            scope = {"spec": spec, "pages": 0, "listingComplete": False, "retainedRows": 0}
            inventory["scopes"].append(scope)
            for page_no in range(args.max_transfer_pages):
                value = reader.request(TRANSFERS_API, {**spec, **({"resume_token": token} if token is not None else {})})
                rows, token, order = validate_transfers(value, spec, token, order)
                for row in rows:
                    identity = (row["receipt_id"], row["asset_id"], int(row["transfer_index"]))
                    if identity in seen:
                        raise ValueError("duplicate incoming indexed transfer")
                    seen.add(identity)
                    incoming.append(row)
                scope.update({"pages": page_no+1, "retainedRows": scope["retainedRows"]+len(rows), "nextToken": token})
                print(f"incoming asset={asset} page={page_no+1} rows={len(rows)} complete={token is None}", flush=True)
                if token is None:
                    scope["listingComplete"] = True
                    break
            if token is not None:
                raise CheckpointStop("incoming per-asset page cap; replay resumes cached pages")
        inventory["listingComplete"] = True
        inventory["retainedRows"] = len(incoming)
        inventory["byAsset"] = dict(Counter(r["asset_id"] for r in incoming))
        # Verify every indexed token-deposit candidate. Other internal incoming
        # settlement credits are inventoried, not falsely called new deposits.
        deposit_rows = [r for r in incoming if r["asset_id"].startswith("nep245:intents.near:")
                        and r.get("other_account_id") is None]
        missing_ids = [r for r in deposit_rows if not r.get("transaction_id")]
        if missing_ids:
            raise CheckpointStop("deposit rows have missing root IDs; receipt lookup required")
        deposit_trees = obtain([r["transaction_id"] for r in deposit_rows])
        deposits = [m for t in deposit_trees for m in mint_deposits(t, SHARED)]
        by_event = {(m["receiptId"], m["logIndex"], "nep245:intents.near:"+m["token"], m["amountRaw"]): m for m in deposits}
        inventory["depositCandidateRows"] = len(deposit_rows)
        inventory["depositCandidateRoots"] = len(deposit_trees)
        result["unreconciledDepositRows"] = []
        for row in deposit_rows:
            key = (row["receipt_id"], row["log_index"], row["asset_id"], str(int(row["amount"])))
            if key not in by_event:
                result["unreconciledDepositRows"].append(row)
        result["mintDeposits"] = deposits
        result["explicitExternalDeposits"] = [m for m in deposits if m["externalDeposits"]]
        result["externalChainCounts"] = dict(Counter(d["memo"].get("networkType") for m in result["explicitExternalDeposits"] for d in m["externalDeposits"]))
        result["directDepositsAndRefunds"] = [m for m in deposits if not m["externalDeposits"]]
        # nzec is funded through its own connector, not OMFT's BRIDGED_FROM
        # memo. Reconcile both direct-to-Intents and preceding wallet mints.
        nzec = [m for m in deposits if m["token"] == "nep141:nzec.bridge.near"]
        links = [link for m in nzec for link in connector_deposit_links(trees[m["nearRoot"]], m["receiptId"],
                                                                      "intents.near", m["amountRaw"], SHARED)]
        wallet_spec = {"account_id": SHARED, "asset_id": "nep141:nzec.bridge.near", "direction": "receiver",
                       "desc": False, "to_timestamp_ms": CUTOFF_NS//1000000, "limit": 100}
        wallet_page = reader.request(TRANSFERS_API, wallet_spec)
        wallet_rows, next_token, _ = validate_transfers(wallet_page, wallet_spec, None)
        if next_token is not None:
            raise CheckpointStop("wallet nzec funding has additional pages; no complete-wallet claim")
        result["walletNzecIncomingInventory"] = {"spec": wallet_spec, "listingComplete": True, "rows": wallet_rows}
        for row in wallet_rows:
            if not row.get("transaction_id"):
                raise CheckpointStop("wallet nzec funding missing root; receipt lookup required")
            tree = obtain([row["transaction_id"]])[0]
            links.extend(connector_deposit_links(tree, row["receipt_id"], SHARED, str(int(row["amount"]))))
        result["nzecZcashDepositLinks"] = links
        for link in links:
            detail = reader.request(f"{ZEC_API}/tx/{link['zecTxid']}")
            if (detail.get("txid") != link["zecTxid"] or detail.get("isCanonical") is not True
                    or detail.get("blockHash") != link["proofBlockHash"] or int(detail["blockHeight"]) > 3488703):
                raise ValueError("Zcash deposit canonical/proof-block metadata disagreement")
            packet = {"hex": link["rawHex"], "expectedTxid": link["zecTxid"],
                      "blockHeight": detail["blockHeight"], "blockTime": detail["blockTime"], "isCanonical": True,
                      "allowV4Transparent": True}
            decoded = json.loads(subprocess.run([str(args.decoder.resolve())], input=json.dumps(packet)+"\n",
                                                text=True, capture_output=True, check=True, timeout=30).stdout)
            if not decoded.get("ok"):
                raise ValueError("Zcash deposit decoding failed: " + str(decoded.get("error")))
            output = next(o for o in decoded["transparentOutputs"] if o["index"] == link["vout"])
            if int(output["valueZat"]) != int(link["grossDepositZat"]):
                raise ValueError("serialized deposit output disagrees with connector credited outpoint")
            if int(link["grossDepositZat"]) != int(link["netMintZat"])+int(link["protocolFeeZat"])+int(link["relayerFeeZat"]):
                raise ValueError("connector gross/net deposit fee accounting disagreement")
            link.update({"detail": detail, "decoded": decoded, "rawOutpointVerified": True})
        # Preserve the earliest indexed native funding as a separate lead. An
        # EVM-looking NEAR account name is not proof of an EVM-origin deposit.
        # A separate cached first-history page establishes only an earliest
        # indexed native-funding lead; this is not a full native-token history.
        first_page = reader.request(TRANSFERS_API, {"account_id": SHARED, "desc": False,
                                                  "to_timestamp_ms": CUTOFF_NS//1000000, "limit": 100})
        native = [r for r in first_page["transfers"] if r["asset_id"] == "native:near" and r["transfer_type"] == "NativeTransfer"
                  and r.get("other_account_id") not in (None, "system")]
        if native and native[0].get("transaction_id"):
            first = native[0]
            tree = obtain([first["transaction_id"]])[0]
            result["earliestIndexedNativeFunding"] = {"transfer": first, "tree": tree,
                                                      "warning": "NEAR execution account; do not infer EVM control or assign challenge funding from a name."}
        print(f"deposits={len(deposits)} external={len(result['explicitExternalDeposits'])} unreconciled={len(result['unreconciledDepositRows'])}", flush=True)
    except (CheckpointStop, OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as exc:
        stopped = str(exc)
        print("checkpoint stop: " + stopped, flush=True)
    else:
        stopped = None
    finally:
        db.close()
        write_rows(out / "incoming-transfers.jsonl", incoming)
        write_rows(out / "trees.jsonl", [used[h] for h in sorted(used)])
        dump(out / "analysis.json", result)
        dump(out / "manifest.json", {"createdAt": datetime.now(timezone.utc).isoformat(), "stopped": stopped,
                                     "challengeSolved": False, "newHttpCalls": reader.calls,
                                     "inputHashes": {str(p.resolve()): digest(p) for p in [args.branch_dir/"analysis.json", args.branch_dir/"manifest.json", args.ledger_dir/"manifest.json"]},
                                     "reusedInputHashes": reused, "responsesUsed": reader.index,
                                     "scriptSha256": digest(Path(__file__)), "analysisSha256": digest(out/"analysis.json"),
                                     "decoderSha256": digest(args.decoder),
                                     "incomingSha256": digest(out/"incoming-transfers.jsonl"), "treesSha256": digest(out/"trees.jsonl")})
    print(f"done: {out / 'analysis.json'}; stopped={stopped}", flush=True)
    return 2 if stopped else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output-dir", type=Path, default=Path("challenge7-user-origin-data"))
    p.add_argument("--case-dir", type=Path, default=Path("challenge7-account-link-data"))
    p.add_argument("--branch-dir", type=Path, default=Path("challenge7-public-branch-data"))
    p.add_argument("--ledger-dir", type=Path, default=Path("challenge7-withdrawal-ledger-data"))
    p.add_argument("--decoder", type=Path, default=Path("decoder/target/release/note_ledger"))
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--max-http-calls", type=int, default=70)
    p.add_argument("--max-transfer-pages", type=int, default=8, help="Per exact asset, not a wallet-wide completeness claim.")
    p.add_argument("--max-new-roots", type=int, default=500)
    p.add_argument("--delay", type=float, default=10)
    args = p.parse_args()
    if min(args.max_http_calls, args.max_transfer_pages, args.max_new_roots) < 1 or args.delay < 0:
        p.error("limits must be positive and delay nonnegative")
    raise SystemExit(investigate(args))


if __name__ == "__main__":
    main()
