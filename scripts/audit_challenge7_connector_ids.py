#!/usr/bin/env python3
"""Offline reconciliation of listed connector receipts to explicit pending IDs.

Uses successful executor-specific logs and descendant receipt references, not
same-address/nearest-quote associations. A pending ID is not settlement. Missing
outcomes, failed calls, replacement IDs and missing canonical metadata stay open.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from analyze_challenge7_baseline import cache_detail, dump, write_rows
from investigate_challenge7_account_links import SUCCESS
from trace_challenge7_free_near import digest, nested, normalize


def full_tree_rpc_result(entry):
    """Use original FastNear execution outcomes, validating graph and executor.

    This changes only the input schema; it does not make a pending ID a mined tx.
    Receipt receiver and outcome executor must agree, rather than substituting one
    for the other. Every descendant reference must have an observed outcome.
    """
    trace = normalize(entry)
    if not trace["treeReferencesComplete"]:
        raise ValueError("full tree incomplete or malformed")
    outcomes = []
    for item in entry.get("receipts") or []:
        receipt = item.get("receipt") or {}
        execution = item.get("execution_outcome") or {}
        rid = receipt.get("receipt_id")
        if execution.get("id") != rid:
            raise ValueError("receipt/execution identity mismatch")
        outcome = execution.get("outcome") or {}
        if outcome.get("executor_id") != receipt.get("receiver_id"):
            raise ValueError("receipt receiver/executor mismatch")
        outcomes.append({"id": rid, "outcome": outcome})
    return {"transaction": entry["transaction"], "receipts_outcome": outcomes}


def rpc_pending_ids(result, receipt):
    outcomes = result.get("receipts_outcome") or []
    by_id = {o["id"]: o["outcome"] for o in outcomes}
    if len(by_id) != len(outcomes): raise ValueError("duplicate RPC receipt outcome")
    if receipt not in by_id: return [], "listed-receipt-outcome-missing"
    origin = by_id[receipt]
    if origin.get("executor_id") != "zcash-connector.bridge.near": return [], "listed-receipt-executor-mismatch"
    if not set(origin.get("status") or {}) & set(SUCCESS): return [], "listed-receipt-not-successful"
    seen, todo, missing = set(), [receipt], set()
    while todo:
        rid = todo.pop()
        if rid in seen: continue
        seen.add(rid)
        if rid not in by_id: missing.add(rid); continue
        todo += by_id[rid].get("receipt_ids") or []
    if missing: return [], "descendant-outcome-reference-missing"
    ids = []
    for rid in sorted(seen):
        o = by_id[rid]
        if o.get("executor_id") != "zcash-connector.bridge.near" or not set(o.get("status") or {}) & set(SUCCESS): continue
        for index, line in enumerate(o.get("logs") or []):
            event = nested(line)
            if not isinstance(event, dict) or event.get("standard") != "bridge" or event.get("event") != "generate_btc_pending_info": continue
            for d in event.get("data") or []:
                h = d.get("btc_pending_id")
                if not isinstance(h, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", h): raise ValueError("malformed explicit pending ID")
                ids.append({"txid": h.lower(), "eventReceiptId": rid, "logIndex": index})
    return ids, None if ids else "successful-listed-receipt-without-descendant-pending-ID"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--requests", type=Path, default=Path("challenge7-free-raw-rescue-data/combined-raw-withdrawals.jsonl"))
    p.add_argument("--rpc-cache", type=Path, default=Path("challenge7-payout-universe-data/cache/near-archival-rpc-txns"))
    p.add_argument("--summary-cache", type=Path, default=Path("challenge7-payout-universe-data/cache/cipherscan-txns"))
    p.add_argument("--decoded", type=Path, default=Path("challenge7-batch-note-data/decoded-transactions.jsonl"))
    p.add_argument("--full-tree-dir", type=Path, help="Optional original FastNear envelopes with a responseHashes manifest; read-only offline fallback")
    p.add_argument("--output-dir", type=Path, default=Path("challenge7-connector-id-audit-data"))
    a = p.parse_args()
    if any(a.output_dir.resolve() == x.resolve() or x.resolve() in a.output_dir.resolve().parents for x in (a.requests.parent,a.rpc_cache,a.summary_cache,a.decoded.parent)):
        raise ValueError("separate output required")
    a.output_dir.mkdir(parents=True, exist_ok=True)
    by_root = defaultdict(list)
    for l in a.requests.read_text().splitlines():
        r = json.loads(l); by_root[r["nearTransactionHash"]].append(r)
    decoded = {json.loads(l)["txid"] for l in a.decoded.read_text().splitlines()}
    records, inputs, seen_roots, errors = [], [], set(), []
    full_roots, full_inputs = {}, []
    if a.full_tree_dir:
        manifest = json.loads((a.full_tree_dir/"manifest.json").read_text())
        for source in manifest["responseHashes"]:
            path = Path(source["path"])
            if a.full_tree_dir.resolve() not in path.resolve().parents:
                raise ValueError("full-tree envelope outside declared directory")
            if digest(path) != source["sha256"]:
                raise ValueError("full-tree envelope hash mismatch")
            envelope = json.loads(path.read_bytes())
            for entry in envelope.get("transactions") or []:
                h = (entry.get("transaction") or {}).get("hash")
                if h not in by_root: continue
                result = full_tree_rpc_result(entry)
                if h in full_roots and full_roots[h][0] != result:
                    raise ValueError("conflicting full-tree root")
                full_roots[h] = (result, source)
            full_inputs.append(source)
    fallback_used = set()

    def process_request(r, h, result, source, source_kind):
        ids, error = rpc_pending_ids(result, r["receiptId"])
        base = {"nearRoot": h, "listedReceiptId": r["receiptId"], "requestedReceiver": r.get("targetAddress"),
                "nearTime": r.get("blockTime"), "sourceCacheFile": source["path"],
                "sourceCacheSha256": source["sha256"], "sourceKind": source_kind}
        if error and h in full_roots and source_kind != "original-fastnear-full-tree":
            replacement, reference = full_roots[h]
            ids, fallback_error = rpc_pending_ids(replacement, r["receiptId"])
            if not fallback_error:
                fallback_used.add(h)
                base.update(sourceCacheFile=reference["path"], sourceCacheSha256=reference["sha256"],
                            sourceKind="original-fastnear-full-tree", priorRpcError=error)
                error = None
        if error: errors.append({**base, "error": error})
        for found in ids:
            txid = found["txid"]; detail = cache_detail(a.summary_cache, txid)
            metadata = bool(detail.get("txid") == txid and detail.get("isCanonical") is True)
            records.append({**base, **found, "evidenceClass": "successful-descendant-pending-ID-not-settlement-by-itself",
                "cachedCanonicalMetadata": metadata, "blockHeight": detail.get("blockHeight") if metadata else None,
                "hasIronwood": detail.get("hasIronwood") if metadata else None,
                "hasOrchard": detail.get("hasOrchard") if metadata else None,
                "beforeTargetAnchor": int(detail["blockHeight"]) <= 3488703 if metadata else None,
                "alreadyBatchDecoded": txid in decoded})
    files = sorted(a.rpc_cache.glob("*.json"))
    for number, path in enumerate(files, 1):
        payload = path.read_bytes()
        result = json.loads(payload).get("result") or {}
        h = (result.get("transaction") or {}).get("hash")
        if h in by_root:
            if h in seen_roots: raise ValueError("duplicate cached requested RPC root")
            seen_roots.add(h)
            fingerprint = hashlib.sha256(payload).hexdigest()
            inputs.append({"path": str(path.resolve()), "sha256": fingerprint})
            for r in by_root[h]:
                process_request(r, h, result, {"path": str(path.resolve()), "sha256": fingerprint}, "cached-near-rpc")
        if number%2000 == 0: print(f"offline RPC roots={number}/{len(files)} pendingEvents={len(records)} unresolved={len(errors)}", flush=True)
    for h in sorted(set(by_root)-seen_roots):
        for r in by_root[h]:
            if h in full_roots:
                result, source = full_roots[h]
                process_request(r, h, result, source, "original-fastnear-full-tree")
                fallback_used.add(h)
            else: errors.append({"nearRoot": h, "listedReceiptId": r["receiptId"], "error": "RPC-root-cache-missing"})
    write_rows(a.output_dir/"pending-ids.jsonl", records)
    write_rows(a.output_dir/"unresolved-requests.jsonl", errors)
    missing = [r for r in records if not r["cachedCanonicalMetadata"]]
    write_rows(a.output_dir/"payouts-without-canonical-summary.jsonl", missing)
    eligible = [r for r in records if r["beforeTargetAnchor"] and r["hasIronwood"] and not r["alreadyBatchDecoded"]]
    write_rows(a.output_dir/"additional-ironwood-candidates.jsonl", eligible)
    dump(a.output_dir/"manifest.json", {"challengeSolved": False, "newHttpCalls": 0, "listedReceipts": sum(map(len,by_root.values())),
         "cachedRootsInspected": len(seen_roots), "explicitPendingEvents": len(records), "distinctPendingIds": len({r["txid"] for r in records}),
         "unresolvedRequests": len(errors), "unresolvedReasons": dict(Counter(r["error"] for r in errors)),
         "eventsWithoutCanonicalSummary": len(missing), "additionalKnownPreAnchorIronwoodEvents": len(eligible),
         "requestsSha256": digest(a.requests), "decodedSha256": digest(a.decoded), "scriptSha256": digest(Path(__file__)),
         "inputRpcCacheHashes": inputs, "pendingIdsSha256": digest(a.output_dir/"pending-ids.jsonl"),
         "fullTreeRootsAvailable": len(full_roots), "fullTreeFallbackRootsUsed": len(fallback_used),
         "originalFullTreeEnvelopes": full_inputs,
         "warning": "Declared cached receipt scope only. Pending IDs require mined identity/receiver/serialization verification; unresolved requests are not exclusions."})
    print(json.dumps({k:v for k,v in json.loads((a.output_dir/"manifest.json").read_text()).items() if k not in ("inputRpcCacheHashes", "originalFullTreeEnvelopes")}), flush=True)


if __name__ == "__main__": main()
