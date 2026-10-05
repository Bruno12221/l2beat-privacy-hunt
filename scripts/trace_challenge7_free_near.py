#!/usr/bin/env python3
"""Bounded, resumable NEAR payout-path investigation without Dune or paid keys.

Default: replay local cache only. --fetch opts into at most --limit transaction
lookups, batched (max 20) through FastNear's documented transactions endpoint.
Stores original responses and decodes ALL function calls, not just root actions.
No transaction is submitted. A 429/401/403 checkpoints and stops immediately.
An indexed call tree is evidence of NEAR execution, not a Zcash spent-note link.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from collect_challenge7_payout_universe import dump_json, load_records, write_jsonl, atomic_write, normalize_raw_rpc_detail, reconcile
from analyze_challenge7_baseline import payout_txids

API = "https://tx.main.fastnear.com/v0/transactions"
DIAGNOSTICS = [
    "98d1291147685549a1c94a27685385fd126efe24c797da867ab12e7be23fb31e",
    "63bc144c8d8ab3e25cec50b57c667323ba32cc9498c9973f25a98e43b07437c8",
    "a023ad5b2016b15f8c5b713c7d72c73fe33d4bfd84c0df9759c613766211baa6",
]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for data in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def nested(value, depth=0):
    """Decode nested JSON strings, never eval/unescape arbitrary bytes."""
    if depth >= 12:
        return value
    if isinstance(value, dict):
        return {key: nested(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [nested(item, depth + 1) for item in value]
    if isinstance(value, str):
        candidate = value.strip()
        for prefix in ("EVENT_JSON:", "BRIDGED_FROM:"):
            if candidate.startswith(prefix):
                candidate = candidate[len(prefix):]
        if candidate.startswith(("{", "[", '"')):
            try:
                return nested(json.loads(candidate), depth + 1)
            except json.JSONDecodeError:
                pass
    return value


def decode_args(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
        try:
            return nested(json.loads(raw)), None
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Borsh/binary arguments are legitimate. Preserve, do not pretend
            # they were parsed JSON or label the receipt tree incomplete.
            return {"nonJsonHex": raw.hex()}, None
    except (ValueError, TypeError) as exc:
        return None, str(exc)


def ns_iso(value):
    if value is None:
        return None
    seconds, fraction = divmod(int(value), 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def status(outcome):
    value = outcome.get("status") or {}
    return next(iter(value), "unknown") if isinstance(value, dict) else str(value)


def normalize(entry):
    tx = entry["transaction"]
    txhash = tx["hash"]
    root_exec = entry.get("execution_outcome") or {}
    receipts = entry.get("receipts") or []
    calls, logs, outcomes = [], [], []
    errors = []

    def actions(source, actions, execution, receipt_id, predecessor, receiver):
        outcome = execution.get("outcome") or {}
        for index, action in enumerate(actions):
            # NEAR's payload-free CreateAccount variant is a JSON string,
            # including in receipts which also contain FunctionCall actions.
            # Keep original indexes; don't mistake this non-call for lost data.
            if action == "CreateAccount":
                continue
            if not isinstance(action, dict):
                errors.append(f"{receipt_id or txhash}:{index}: unsupported action shape/type {type(action).__name__}")
                continue
            call = action.get("FunctionCall")
            if "FunctionCall" in action and not isinstance(call, dict):
                errors.append(f"{receipt_id or txhash}:{index}: malformed FunctionCall payload")
                continue
            if not isinstance(call, dict):
                continue
            args, error = decode_args(call.get("args"))
            calls.append({
                "nearTransactionHash": txhash, "source": source,
                "receiptId": receipt_id, "actionIndex": index,
                "predecessor": predecessor, "receiver": receiver,
                "method": call.get("method_name"), "args": args,
                "argsBase64": call.get("args"), "argsError": error,
                "attachedDepositYoctoNear": call.get("deposit"),
                "blockHeight": execution.get("block_height"),
                "blockTimestampNs": str(execution["block_timestamp"]) if execution.get("block_timestamp") is not None else None,
                "blockTime": ns_iso(execution.get("block_timestamp")),
                "executionStatus": status(outcome),
            })
            if error:
                errors.append(f"{receipt_id or txhash}:{index}: {error}")

    actions("transaction", tx.get("actions") or [], root_exec, None, tx.get("signer_id"), tx.get("receiver_id"))
    observed_ids = set()
    referenced_ids = set((root_exec.get("outcome") or {}).get("receipt_ids") or [])
    for item in receipts:
        receipt = item.get("receipt") or {}
        execution = item.get("execution_outcome") or {}
        outcome = execution.get("outcome") or {}
        rid = receipt.get("receipt_id") or execution.get("id")
        if not rid or rid in observed_ids:
            errors.append(f"missing/duplicate receipt id: {rid}")
        observed_ids.add(rid)
        referenced_ids.update(outcome.get("receipt_ids") or [])
        body = (receipt.get("receipt") or {}).get("Action") or {}
        actions("receipt", body.get("actions") or [], execution, rid, receipt.get("predecessor_id"), receipt.get("receiver_id"))
        outcomes.append({"receiptId": rid, "receiver": receipt.get("receiver_id"),
                         "blockHeight": execution.get("block_height"), "blockHash": execution.get("block_hash"),
                         "executionStatus": status(outcome), "status": outcome.get("status"),
                         "childReceiptIds": outcome.get("receipt_ids") or []})
        for index, log in enumerate(outcome.get("logs") or []):
            logs.append({"nearTransactionHash": txhash, "receiptId": rid, "index": index,
                         "receiver": receipt.get("receiver_id"), "blockHeight": execution.get("block_height"),
                         "log": log, "decoded": nested(log)})
    missing = sorted(referenced_ids - observed_ids)
    return {"nearTransactionHash": txhash, "signer": tx.get("signer_id"),
            "receiver": tx.get("receiver_id"), "blockHeight": root_exec.get("block_height"),
            "blockTime": ns_iso(root_exec.get("block_timestamp")),
            "receiptCount": len(receipts), "missingReferencedReceiptIds": missing,
            "treeReferencesComplete": not missing and not errors,
            "decodeErrors": errors, "calls": calls, "logs": logs, "outcomes": outcomes,
            "warning": "Indexer execution tree; not a public Zcash note-to-spend proof. Shared relayers/solvers do not prove shared ownership."}


def withdrawal_records(trace, queue_row):
    """Extract executed token calls; root signed intents are not executed twice."""
    result = []
    for call in trace["calls"]:
        args = call.get("args")
        if call["source"] != "receipt" or call["receiver"] != "zec.omft.near" or not isinstance(args, dict):
            continue
        receiver, path = None, None
        if call["method"] == "ft_transfer" and args.get("receiver_id") == "zec.omft.near" and str(args.get("memo") or "").startswith("WITHDRAW_TO:"):
            receiver = args["memo"][len("WITHDRAW_TO:"):]
            path = "legacy-token-self-transfer-memo"
        elif call["method"] == "ft_transfer_call" and args.get("receiver_id") == "omni.bridge.near":
            msg = args.get("msg") or {}
            if isinstance(msg, dict) and str(msg.get("recipient") or "").startswith("zcash:"):
                receiver = msg["recipient"][len("zcash:"):]
                path = "omni-bridge-transfer-call"
        if receiver is None:
            continue
        matching = [row for row in queue_row.get("routes") or [] if row.get("recipient") == receiver]
        signed_withdrawals = []
        for entry in trace["calls"]:
            if entry["source"] != "receipt" or entry["method"] != "execute_intents":
                continue
            for signed in (entry.get("args") or {}).get("signed") or []:
                payload = signed.get("payload") or {}
                if not isinstance(payload, dict):
                    continue
                message = payload.get("message") or {}
                if not isinstance(message, dict):
                    continue
                for intent in message.get("intents") or []:
                    memo = str(intent.get("memo") or "")
                    msg = intent.get("msg") or {}
                    intent_receiver = memo[len("WITHDRAW_TO:"):] if memo.startswith("WITHDRAW_TO:") else (
                        str(msg.get("recipient") or "")[len("zcash:"):] if isinstance(msg, dict) and str(msg.get("recipient") or "").startswith("zcash:") else None)
                    if intent.get("intent") == "ft_withdraw" and intent_receiver == receiver and str(intent.get("amount")) == str(args.get("amount")):
                        signed_withdrawals.append({"intentsAccountId": message.get("signer_id"),
                                                   "publicKey": signed.get("public_key"), "standard": signed.get("standard")})
        result.append({"nearTransactionHash": trace["nearTransactionHash"], "receiptId": call["receiptId"], "actionIndex": call["actionIndex"],
                       "blockTime": call["blockTime"], "withdrawalPath": path,
                       "requestedReceiver": receiver, "requestedAmountZat": str(args.get("amount")),
                       "executionStatus": call["executionStatus"], "signedWithdrawalAccounts": signed_withdrawals,
                       "explorerAssociatedPayoutTxids": queue_row["payoutTxids"], "matchingExplorerRoutes": matching,
                       "warning": "Requested amount, not a decoded Zcash output note. Explorer association plus matching receiver is not a commitment-to-nullifier proof."})
    return result


def make_queue(routes, targets):
    by_hash = {}
    for route in routes:
        associated = sorted(set(payout_txids(route)) & set(targets))
        if not associated:
            continue
        for txhash in route.get("nearTxHashes") or []:
            row = by_hash.setdefault(txhash, {"nearTransactionHash": txhash, "payoutTxids": [], "routes": []})
            row["payoutTxids"] = sorted(set(row["payoutTxids"]) | set(associated))
            metadata = {key: route.get(key) for key in (
                "createdAt", "depositAddress", "recipient", "recipientType", "originAsset",
                "originChainTxHashes", "senders", "refundTo", "referral", "amountOut")}
            row["routes"].append(metadata)
    return [by_hash[key] for key in sorted(by_hash)]


def raw_error_queue(universe):
    errors = {row["nearTransactionHash"]: row for row in load_records(universe / "raw-detail-errors.json")}
    for row in load_records(universe / "raw-withdrawals.jsonl"):
        if not row.get("parseOk"):
            errors.setdefault(row["nearTransactionHash"], {"error": "original root-only parser did not recognize request"})
    receipts = defaultdict(list)
    for row in load_records(universe / "raw-near-receipts.jsonl"):
        if row.get("transaction_hash") in errors:
            receipts[row["transaction_hash"]].append(row)
    return [{"nearTransactionHash": txhash, "payoutTxids": [], "routes": [],
             "rawReceipts": receipts[txhash], "previousError": errors[txhash].get("error")}
            for txhash in sorted(errors)]


def normalize_connector_request(receipt, entry, trace):
    """Prefer the specific executed connector receipt over a guessed root method."""
    row = normalize_raw_rpc_detail(receipt, {"result": {"transaction": entry["transaction"]}})
    row["detailSource"] = "fastnear-indexed-full-tree"
    row["indexedTreeReferencesComplete"] = trace["treeReferencesComplete"]
    row["receiptOutcome"] = next((r["status"] for r in trace["outcomes"] if r["receiptId"] == receipt.get("receipt_id")), None)
    for call in trace["calls"]:
        if call["source"] != "receipt" or call["receiptId"] != receipt.get("receipt_id") or call["receiver"] != "zcash-connector.bridge.near" or call["method"] != "ft_on_transfer":
            continue
        args = call.get("args") or {}
        message = args.get("msg") or {}
        withdraw = message.get("Withdraw") if isinstance(message, dict) else None
        if not isinstance(withdraw, dict):
            continue
        row.update({"targetAddress": withdraw.get("target_btc_address"),
                    "transparentOutputs": withdraw.get("output") or [], "connectorInputs": withdraw.get("input") or [],
                    "maxGasFee": withdraw.get("max_gas_fee"), "requestedTokenAmountZat": args.get("amount"),
                    "expiryHeight": withdraw.get("expiry_height") or (withdraw.get("chain_specific_data") or {}).get("expiry_height"),
                    "parseOk": bool(withdraw.get("target_btc_address")), "parsedFromExecutedReceipt": True})
        break
    return row


class CheckpointStop(Exception):
    pass


def fetch_batch(hashes, output, delay, timeout, attempts):
    body = json.dumps({"tx_hashes": hashes}, separators=(",", ":")).encode()
    key = hashlib.sha256(API.encode() + b"\n" + body).hexdigest()
    path = output / "responses" / f"{key}.json"
    # The main cache replay already removes successful hashes. If this exact
    # pending batch previously returned missing/incomplete records, try fresh
    # data; preserve the preceding original response before replacing it.
    for attempt in range(attempts):
        # Sequential pacing across batches, including the first one, and retries.
        time.sleep(delay if attempt == 0 else max(delay, 2 ** attempt))
        req = urllib.request.Request(API, data=body, headers={
            "content-type": "application/json", "accept": "application/json",
            "user-agent": "l2beat-privacy-hunt-research/2.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                value = json.load(response)
            if not isinstance(value, dict) or not isinstance(value.get("transactions"), list):
                raise ValueError("unexpected transactions API response shape")
            if path.exists():
                previous = hashlib.sha256(path.read_bytes()).hexdigest()
                archived = output / "responses-history" / f"{previous}.json"
                if not archived.exists():
                    atomic_write(archived, path.read_text())
            dump_json(path, value)
            return value, path, True
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 429):
                raise CheckpointStop(f"HTTP {exc.code}; Retry-After={exc.headers.get('Retry-After')}; stopped, no automatic provider rotation or purchase") from exc
            if exc.code < 500 or attempt + 1 == attempts:
                raise RuntimeError(f"HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionError):
            if attempt + 1 == attempts:
                raise
    raise RuntimeError("request attempts exhausted")


def audit_raw(universe, output):
    paths = {name: universe / filename for name, filename in (
        ("receipts", "raw-near-receipts.jsonl"), ("withdrawals", "raw-withdrawals.jsonl"),
        ("errors", "raw-detail-errors.json"), ("reconciliation", "reconciliation.jsonl"))}
    if not all(path.exists() for path in paths.values()):
        return {"available": False}
    rows = {name: load_records(path) for name, path in paths.items()}
    errors = rows["errors"]
    missing = [row for row in rows["reconciliation"] if row.get("routeMatchStatus") == "missing"]
    failures = []
    for row in rows["receipts"]:
        state = (row.get("outcome") or {}).get("status")
        if state is False:
            failures.append(row)
    result = {
        "available": True, "receiptCount": len(rows["receipts"]),
        "normalizedDetailCount": len(rows["withdrawals"]), "detailErrorCount": len(errors),
        "detail429Count": sum("429" in row.get("error", "") for row in errors),
        "unparsedDetails": sum(not row.get("parseOk") for row in rows["withdrawals"]),
        "failedListedReceiptCount": len(failures),
        "reconciliationStatuses": dict(Counter(row.get("routeMatchStatus") for row in rows["reconciliation"])),
        "missingByPredecessor": dict(Counter(row.get("predecessorAccountId") for row in missing)),
        "missingByReceiverShape": dict(Counter(
            "unparsed" if not row.get("targetAddress") else "unified" if row["targetAddress"].startswith("u1")
            else "transparent-or-tex" if row["targetAddress"].startswith("t") else "other" for row in missing)),
        "missingByMonth": dict(Counter(str(row.get("blockTime"))[:7] for row in missing)),
        "receiptsByMonthAndPredecessor": dict(Counter(
            str(ns_iso((row.get("block") or {}).get("block_timestamp")))[:7] + " / " + str(row.get("predecessor_account_id"))
            for row in rows["receipts"])),
        "inputHashes": {name: {"path": str(path.resolve()), "sha256": digest(path)} for name, path in paths.items()},
        "warning": "Finished is not exhaustive: collector listed only one connector/method. Exact whole-address reconciliation misses internal receiver equivalence, non-explorer routes and failed requests; nearest quote time is not proof."}
    dump_json(output / "raw-run-audit.json", result)
    write_jsonl(output / "unmatched-raw-requests.jsonl", missing)
    write_jsonl(output / "unparsed-raw-requests.jsonl", [row for row in rows["withdrawals"] if not row.get("parseOk")])
    write_jsonl(output / "failed-listed-receipts.jsonl", failures)
    return result


def report(output, queue, traces, errors, audit, stopped, elapsed, network_batches):
    relevant = {row["nearTransactionHash"] for row in queue}
    selected = [row for key, row in sorted(traces.items()) if key in relevant]
    calls = [call for row in selected for call in row["calls"]]
    methods = Counter((call["receiver"], call["method"]) for call in calls if call["source"] == "receipt")
    queue_by_hash = {row["nearTransactionHash"]: row for row in queue}
    withdrawals = [withdrawal for trace in selected for withdrawal in withdrawal_records(trace, queue_by_hash[trace["nearTransactionHash"]])]
    write_jsonl(output / "withdrawals.jsonl", withdrawals)
    write_jsonl(output / "traces.jsonl", selected)
    write_jsonl(output / "calls.jsonl", calls)
    write_jsonl(output / "logs.jsonl", [log for row in selected for log in row["logs"]])
    dump_json(output / "errors.json", list(errors.values()))
    stats = {"queueCount": len(queue), "tracedCount": len(selected), "calls": len(calls),
             "completeReferenceTrees": sum(row["treeReferencesComplete"] for row in selected),
             "receiptCallMethods": [{"receiver": pair[0], "method": pair[1], "count": count} for pair, count in methods.most_common()],
             "withdrawalPaths": dict(Counter(row["withdrawalPath"] for row in withdrawals)),
             "stopped": stopped, "elapsedSeconds": round(elapsed, 2), "networkBatchesThisRun": network_batches,
             "recoveredRawRequestDetails": len(load_records(output / "rescued-raw-withdrawals.jsonl")),
             "notTracedHashes": sorted(relevant - set(traces)), "rawAudit": audit}
    dump_json(output / "summary.json", stats)
    text = ["# Challenge 7: free NEAR path diagnostics", "", "Challenge remains unresolved. No Dune or paid API key used.", "",
            f"Requested NEAR roots: {len(queue)}; traced: {len(selected)}; function calls: {len(calls)}.",
            f"Trees with no missing referenced receipts or decoding errors: {stats['completeReferenceTrees']}.",
            f"New batched HTTP requests this run: {network_batches}; elapsed: {elapsed:.1f} seconds.", ""]
    if stopped:
        text.extend([f"Stopped safely: {stopped}", ""])
    text.extend(["## Observed receipt call paths", "", "| Receiver | Method | Count |", "| --- | --- | --- |"])
    text.extend(f"| `{account}` | `{method}` | {count} |" for (account, method), count in methods.most_common())
    text.extend(["", "## Root transactions", "", "| NEAR hash | Time | Signer | Receiver | Receipts |", "| --- | --- | --- | --- | --- |"])
    text.extend(f"| `{row['nearTransactionHash']}` | {row['blockTime']} | `{row['signer']}` | `{row['receiver']}` | {row['receiptCount']} |" for row in selected)
    text.extend(["", "## Evidence limits", "",
                 "Original API responses are retained with byte hashes. Calls retain raw base64 and recursively decoded JSON arguments. Root and receipt calls are separate to prevent double-counting executions.",
                 "A listed child receipt being present is a structural completeness check, not independent verification of indexer data or all historical paths. Failed receipts are retained. Shared infrastructure accounts are not shared-wallet ownership evidence.",
                 "Matching a route/withdrawal on NEAR does not publicly link a Zcash output commitment to the target nullifier. Requested withdrawal amounts and public pool net balances are not necessarily exact user output note amounts.", ""])
    text.extend(["## Observed Zcash withdrawal requests", "", "| Time | Path | Requested zats | Matching explorer receivers |", "| --- | --- | --- | --- |"])
    text.extend(f"| {row['blockTime']} | {row['withdrawalPath']} | {row['requestedAmountZat']} | {len(row['matchingExplorerRoutes'])} |" for row in withdrawals)
    text.append("")
    if audit.get("available"):
        text.extend(["## Finished raw run", "",
                     f"Receipts {audit['receiptCount']}; details {audit['normalizedDetailCount']}; errors {audit['detailErrorCount']} ({audit['detail429Count']} contain 429); unparsed details {audit['unparsedDetails']}.",
                     "Whole-address matches: " + json.dumps(audit["reconciliationStatuses"], sort_keys=True) + ".",
                     audit["warning"], ""])
        if audit.get("combinedReplay"):
            merged = audit["combinedReplay"]
            text.extend(["## Combined request replay", "",
                         f"Details: {merged['details']}/{merged['listedReceiptCount']} listed receipts; parsed receivers: {merged['parsedReceivers']}; separately rescued/reparsed: {merged['rescuedDetails']}.",
                         "Whole-address statuses: " + json.dumps(merged["statuses"], sort_keys=True) + ".",
                         merged["warning"], ""])
    atomic_write(output / "report.md", "\n".join(text))
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--routes", type=Path, default=Path("challenge7-complete-routes/all_routes.jsonl"))
    parser.add_argument("--universe", type=Path, default=Path("challenge7-payout-universe-data"))
    parser.add_argument("--output-dir", type=Path, default=Path("challenge7-free-trace-data"))
    parser.add_argument("--payout", action="append", help="Zcash payout txid; repeatable. Default: three legacy/current diagnostics.")
    parser.add_argument("--unrecovered-sample", type=Path, help="Decoded transaction ledger: trace every unrecovered positive Ironwood payout plus earliest and latest recovered controls.")
    parser.add_argument("--raw-errors", action="store_true", help="Instead trace failed or unparsed raw NEAR roots. Writes rescued details separately; never modifies old collector data.")
    parser.add_argument("--fetch", action="store_true", help="Opt into bounded public HTTP fetches, without any API key.")
    parser.add_argument("--limit", type=int, default=80, help="Maximum NEAR roots to fetch per invocation, not number of batches.")
    parser.add_argument("--batch-size", type=int, default=10, choices=range(1, 21), metavar="1..20")
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--attempts", type=int, default=2)
    args = parser.parse_args()
    if args.limit <= 0 or args.delay < 1 or args.timeout <= 0 or args.attempts not in range(1, 4):
        parser.error("require positive limit/timeout, delay >= 1 second, attempts 1..3")
    started = time.monotonic()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    targets = list(args.payout or DIAGNOSTICS)
    input_paths = [Path(__file__), Path(__file__).with_name("collect_challenge7_payout_universe.py"),
                   Path(__file__).with_name("analyze_challenge7_baseline.py"), args.routes]
    if args.unrecovered_sample:
        input_paths.append(args.unrecovered_sample)
        decoded = load_records(args.unrecovered_sample)
        recovered = []
        for row in decoded:
            if not row.get("ok"):
                continue
            positive = any(item.get("pool") == "ironwood" and item.get("valueBalanceZat", 0) < 0 for item in row.get("bundles") or [])
            outputs = [item for item in row.get("outputs") or [] if item.get("pool") == "ironwood" and item.get("recovered") and item.get("valueZat", 0) > 0]
            if positive and not outputs:
                targets.append(row["txid"])
            elif outputs:
                recovered.append(row)
        recovered.sort(key=lambda row: row.get("blockHeight") or 0)
        if recovered:
            targets.extend([recovered[0]["txid"], recovered[-1]["txid"]])
    targets = sorted(set(targets))
    routes = load_records(args.routes)
    queue = raw_error_queue(args.universe) if args.raw_errors else make_queue(routes, targets)
    if args.raw_errors:
        input_paths.extend([args.universe / "raw-detail-errors.json", args.universe / "raw-near-receipts.jsonl", args.universe / "raw-withdrawals.jsonl"])
    write_jsonl(output / "queue.jsonl", queue)
    traces, cache_manifest = {}, []
    # Replay all original indexed responses. Never rely on an old normalized file.
    raw_entries = {}
    for path in sorted((output / "responses").glob("*.json")):
        response = json.loads(path.read_text())
        for entry in response.get("transactions") or []:
            row = normalize(entry)
            traces[row["nearTransactionHash"]] = row
            raw_entries[row["nearTransactionHash"]] = entry
        cache_manifest.append({"path": str(path.resolve()), "sha256": digest(path)})
    errors = {row["nearTransactionHash"]: row for row in load_records(output / "errors.json")}
    pending = [row["nearTransactionHash"] for row in queue if row["nearTransactionHash"] not in traces or not traces[row["nearTransactionHash"]]["treeReferencesComplete"]][:args.limit]
    stopped, network_batches = None, 0
    if args.fetch:
        try:
            for offset in range(0, len(pending), args.batch_size):
                hashes = pending[offset:offset + args.batch_size]
                response, path, fetched = fetch_batch(hashes, output, args.delay, args.timeout, args.attempts)
                network_batches += int(fetched)
                cache_manifest.append({"path": str(path.resolve()), "sha256": digest(path)})
                returned = set()
                for entry in response["transactions"]:
                    txhash = entry.get("transaction", {}).get("hash")
                    if txhash not in hashes or txhash in returned:
                        raise ValueError("unrequested/duplicate transaction in batch response")
                    returned.add(txhash)
                    row = normalize(entry)
                    traces[txhash] = row
                    raw_entries[txhash] = entry
                    errors.pop(txhash, None)
                for txhash in set(hashes) - returned:
                    errors[txhash] = {"nearTransactionHash": txhash, "error": "API returned no record; not evidence the transaction does not exist"}
                dump_json(output / "errors.json", list(errors.values()))
                print(f"batch={offset // args.batch_size + 1} roots={len(returned)}/{len(hashes)} traced={len(traces)}/{len(queue)} incomplete={sum(not row['treeReferencesComplete'] for row in traces.values())}", flush=True)
        except KeyboardInterrupt:
            stopped = "interrupted by user; original responses checkpointed"
        except Exception as exc:
            stopped = str(exc)
            print(f"checkpoint stop: {stopped}", flush=True)
    audit = audit_raw(args.universe, output)
    rescued = []
    for item in queue:
        txhash = item["nearTransactionHash"]
        if txhash not in raw_entries:
            continue
        for receipt in item.get("rawReceipts") or []:
            rescued.append(normalize_connector_request(receipt, raw_entries[txhash], traces[txhash]))
    if args.raw_errors:
        write_jsonl(output / "rescued-raw-withdrawals.jsonl", rescued)
        combined = {(row.get("nearTransactionHash"), row.get("receiptId")): row
                    for row in load_records(args.universe / "raw-withdrawals.jsonl")}
        for row in rescued:
            combined[(row.get("nearTransactionHash"), row.get("receiptId"))] = row
        combined_rows = sorted(combined.values(), key=lambda row: row.get("blockTime") or "")
        write_jsonl(output / "combined-raw-withdrawals.jsonl", combined_rows)
        matches = reconcile(combined_rows, routes)
        write_jsonl(output / "combined-address-reconciliation.jsonl", matches)
        combined_audit = {"details": len(combined_rows), "parsedReceivers": sum(bool(row.get("parseOk")) for row in combined_rows),
                          "originalDetails": audit.get("normalizedDetailCount"), "rescuedDetails": len(rescued),
                          "listedReceiptCount": audit.get("receiptCount"),
                          "statuses": dict(Counter(row.get("routeMatchStatus") for row in matches)),
                          "warning": "Combined replay is complete only for the listed connector receipts. Whole-address/nearest-quote reconciliation is a diagnostic, not deterministic attribution."}
        dump_json(output / "combined-raw-audit.json", combined_audit)
        audit["combinedReplay"] = combined_audit
    manifest = {"createdAt": datetime.now(timezone.utc).isoformat(), "endpoint": API,
                "payoutTargets": targets, "inputHashes": [{"path": str(path.resolve()), "sha256": digest(path)} for path in input_paths],
                "responseHashes": list({row["path"]: row for row in cache_manifest}.values()),
                "queueCount": len(queue), "fetchRequested": args.fetch, "rootLimit": args.limit,
                "batchSize": args.batch_size, "delaySeconds": args.delay,
                "rawErrorMode": args.raw_errors,
                "secretsUsed": False, "challengeSolved": False}
    dump_json(output / "manifest.json", manifest)
    stats = report(output, queue, traces, errors, audit, stopped, time.monotonic() - started, network_batches)
    print(f"done: {output}/report.md; traced={stats['tracedCount']}/{stats['queueCount']} stopped={stopped}", flush=True)


if __name__ == "__main__":
    main()
