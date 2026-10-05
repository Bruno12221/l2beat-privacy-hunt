#!/usr/bin/env python3
"""Recover actual note plaintexts using the public read-only raw batch endpoint.

No minimum value or change cap: all queue-listed positive Ironwood inflows before
the target anchor are included. This is a declared payout inventory, not the full
private pool, and successful recovery does not establish subsequent consumption.
Original HTTP bytes are retained; cache-only replay is the default.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import cache_detail, dump, write_rows, zcash_txid
from investigate_challenge7_account_links import Evidence
from trace_challenge7_free_near import CheckpointStop, digest
from trace_challenge7_user_origins import Reader

API = "https://api.mainnet.cipherscan.app/api/tx/raw/batch"
ANCHOR = 3488703


def validate_batch(value, wanted):
    if not isinstance(value, dict) or not isinstance(value.get("transactions"), list):
        raise ValueError("unexpected batch response")
    result, failed = {}, {}
    for row in value["transactions"]:
        txid = row.get("txid")
        if txid not in wanted or txid in result or not isinstance(row.get("hex"), str):
            raise ValueError("unrequested, duplicate or malformed batch transaction")
        bytes.fromhex(row["hex"])
        result[txid] = row
    for row in value.get("failed") or []:
        txid = row.get("txid")
        if txid not in wanted or txid in failed or txid in result:
            raise ValueError("unrequested/duplicate/conflicting failed result")
        failed[txid] = row
    if set(result) | set(failed) != set(wanted) or value.get("total") != len(wanted) or value.get("successful") != len(result):
        raise ValueError("batch count/set reconciliation failed")
    return result, failed


def selected_queue(rows):
    selected = []
    for r in rows:
        if (zcash_txid(r.get("txid")) and int(r.get("ironwoodNetInflowZat") or 0) > 0
                and r.get("blockHeight") is not None and 3428143 <= int(r["blockHeight"]) <= ANCHOR):
            selected.append(r)
    if len({r["txid"] for r in selected}) != len(selected):
        raise ValueError("duplicate queue transaction")
    return sorted(selected, key=lambda r:r["txid"])


def selected_pending_queue(rows):
    """Independent explicit pending IDs, deliberately without block eligibility.

    Fetching serialization establishes ID/output facts, not mined settlement or
    the height needed to enter a target-input search. Do not substitute NEAR time.
    """
    for r in rows:
        if (not zcash_txid(r.get("txid")) or
                r.get("evidenceClass") != "successful-descendant-pending-ID-not-settlement-by-itself"):
            raise ValueError("verified explicit pending-ID row required")
    if len({r["txid"] for r in rows}) != len(rows):
        raise ValueError("duplicate pending-ID row")
    return sorted(rows,key=lambda r:r["txid"])


def investigate(a):
    if a.output_dir.resolve() == a.queue.parent.resolve() or a.queue.parent.resolve() in a.output_dir.resolve().parents:
        raise ValueError("separate output required")
    a.output_dir.mkdir(parents=True, exist_ok=True)
    payload = a.queue.read_bytes()
    queue_hash = hashlib.sha256(payload).hexdigest()
    pending_mode = getattr(a,"pending_ids",False)
    selector = selected_pending_queue if pending_mode else selected_queue
    rows = selector([json.loads(l) for l in payload.splitlines() if l.strip()])
    queue = {r["txid"]: r for r in rows}
    reader = Reader(a.output_dir, a.fetch, a.max_http_calls, a.delay)
    output = a.output_dir/"decoded-transactions.jsonl"
    done, decoded_rows, errors = set(), [], {}
    errors_path = a.output_dir/"errors.json"
    config = {"queueSha256": queue_hash, "decoderSha256": digest(a.decoder), "batchSize": a.batch_size,
              "anchor": ANCHOR, "selection": ("explicit-pending-ID-serialization-only-canonicality-and-height-unverified" if pending_mode
                  else "queue-listed-positive-Ironwood-inflow-height-eligible-no-amount-floor")}
    config_path = a.output_dir/"config.json"
    if config_path.exists() and json.loads(config_path.read_text()) != config:
        raise ValueError("immutable queue/decoder/batch config changed; use a separate output directory")
    dump(config_path, config)
    if output.exists():
        for line in output.read_text().splitlines():
            r = json.loads(line)
            if not r.get("ok") or r["txid"] not in queue or r["txid"] in done:
                raise ValueError("invalid/duplicate/out-of-scope saved decoded output")
            done.add(r["txid"]); decoded_rows.append(r)
    if errors_path.exists(): errors = json.loads(errors_path.read_text())
    started = time.monotonic(); stopped = "unexpected failure before completion"
    process = subprocess.Popen([str(a.decoder.resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        with output.open("a", encoding="utf-8") as handle:
            for offset in range(0, len(rows), a.batch_size):
                batch = rows[offset:offset+a.batch_size]
                wanted = [r["txid"] for r in batch]
                if all(h in done for h in wanted): continue
                # Stable original batches permit exact cache reuse after a stop.
                raw, failed = validate_batch(reader.request(API, {"txids": wanted}), wanted)
                for h, f in failed.items(): errors[h] = {"stage": "batch-source-failed", "result": f}
                for r in batch:
                    h = r["txid"]
                    if h in done or h not in raw: continue
                    detail = {} if pending_mode else cache_detail(a.summary_cache, h)
                    if not pending_mode and (detail.get("txid") != h or detail.get("isCanonical") is not True
                            or int(detail["blockHeight"]) != int(r["blockHeight"])):
                        errors[h] = {"stage": "metadata", "reason": "canonical txid/height disagrees or missing"}
                        continue
                    addresses = ({r["requestedReceiver"]} if pending_mode and str(r.get("requestedReceiver","")).startswith("u1") else
                        {str(l["recipient"]) for l in r.get("routes", []) if str(l.get("recipient", "")).startswith("u1")})
                    packet = {"hex": raw[h]["hex"], "expectedTxid": h,
                              "blockHeight": None if pending_mode else r["blockHeight"],
                              "blockTime": None if pending_mode else r.get("blockTime"),
                              "isCanonical": None if pending_mode else True,
                              "allowV4Transparent": pending_mode, "unifiedAddresses": sorted(addresses)}
                    process.stdin.write(json.dumps(packet)+"\n"); process.stdin.flush()
                    line = process.stdout.readline()
                    if not line: raise CheckpointStop("decoder exited without response")
                    d = json.loads(line)
                    if not d.get("ok") or d.get("txid") != h:
                        errors[h] = {"stage": "decode", "reason": d.get("error") or "expected txid disagreement"}
                        continue
                    # Exact actual raw bytes bind the transaction identity and output
                    # plaintexts. Metadata is a separately preserved indexer claim.
                    d["rawHexSha256"] = hashlib.sha256(bytes.fromhex(raw[h]["hex"])).hexdigest()
                    d["rawSourceEndpoint"] = API
                    if pending_mode:
                        d["pendingRequestProvenance"] = r
                        d["eligibilityWarning"] = "Serialization-only. Canonical block height and inclusion are not established; do not use NEAR execution time as Zcash height."
                    else:
                        d["summaryCacheFile"] = str((a.summary_cache/(hashlib.sha256(("https://api.mainnet.cipherscan.app/api/tx/"+h).encode()).hexdigest()+".json")).resolve())
                        d["summaryCacheSha256"] = digest(Path(d["summaryCacheFile"]))
                    handle.write(json.dumps(d, sort_keys=True)+"\n"); handle.flush()
                    done.add(h); decoded_rows.append(d); errors.pop(h, None)
                dump(errors_path, errors)
                recovered = sum(o.get("recovered") is True and int(o.get("valueZat") or 0)>0 for d in decoded_rows for o in d.get("outputs") or [])
                print(f"raw batches={offset//a.batch_size+1}/{(len(rows)+a.batch_size-1)//a.batch_size} decoded={len(done)}/{len(rows)} positiveNotes={recovered} errors={len(errors)} newHTTP={reader.calls}", flush=True)
        stopped = None
    except (CheckpointStop, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        stopped = str(exc); print("checkpoint stop: "+stopped, flush=True)
    finally:
        process.stdin.close(); process.wait(timeout=30)
        dump(errors_path, errors)
        missing = sorted(set(queue)-done)
        write_rows(a.output_dir/"unresolved-transactions.jsonl", [{"txid": h, "error": errors.get(h)} for h in missing])
        dump(a.output_dir/"manifest.json", {"createdAt": datetime.now(timezone.utc).isoformat(), "stopped": stopped,
             "challengeSolved": False, "scopeComplete": not missing, "selectedTransactions": len(rows),
             "decodedTransactions": len(done), "remainingTransactions": len(missing), "newHttpCalls": reader.calls,
             "responsesUsed": reader.index, "elapsedSeconds": round(time.monotonic()-started, 3), **config,
             "scriptSha256": digest(Path(__file__)), "decodedSha256": digest(output),
             "positiveRecoveredNotes": sum(o.get("recovered") is True and int(o.get("valueZat") or 0)>0 for d in decoded_rows for o in d.get("outputs") or [])})
    return 2 if stopped else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--queue", type=Path, default=Path("challenge7-baseline-v2-data/decode-queue.jsonl"))
    p.add_argument("--pending-ids", action="store_true", help="Decode explicit connector pending IDs without claiming mined height/canonicality; use separate output")
    p.add_argument("--output-dir", type=Path, default=Path("challenge7-batch-note-data"))
    p.add_argument("--summary-cache", type=Path, default=Path("challenge7-payout-universe-data/cache/cipherscan-txns"))
    p.add_argument("--decoder", type=Path, default=Path("decoder/target/release/note_ledger"))
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--batch-size", type=int, default=100)
    p.add_argument("--max-http-calls", type=int, default=2, help="Per invocation; default is a small live benchmark.")
    p.add_argument("--delay", type=float, default=3)
    a = p.parse_args()
    if not 1 <= a.batch_size <= 100 or a.max_http_calls < 1 or a.delay < 1: p.error("batch 1..100, positive HTTP cap, delay >=1 required")
    raise SystemExit(investigate(a))


if __name__ == "__main__": main()
