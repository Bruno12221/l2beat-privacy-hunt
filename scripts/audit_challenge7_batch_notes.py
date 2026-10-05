#!/usr/bin/env python3
"""Offline full replay of raw batch envelopes and every saved decoded transaction.

Verifies preserved source bytes, exact request/result inventories, queue/decoder
hashes and deterministic decoding. This is reproducibility, not independent chain
consensus or a private spent-note proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from analyze_challenge7_baseline import cache_detail, dump
from collect_challenge7_raw_batches import API, selected_queue, selected_pending_queue, validate_batch
from trace_challenge7_free_near import digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data-dir", type=Path, default=Path("challenge7-batch-note-data"))
    p.add_argument("--queue", type=Path, default=Path("challenge7-baseline-v2-data/decode-queue.jsonl"))
    p.add_argument("--pending-ids",action="store_true",help="Replay serialization-only pending-ID mode without inventing metadata")
    p.add_argument("--summary-cache", type=Path, default=Path("challenge7-payout-universe-data/cache/cipherscan-txns"))
    p.add_argument("--decoder", type=Path, default=Path("decoder/target/release/note_ledger"))
    a = p.parse_args()
    config = json.loads((a.data_dir/"config.json").read_text())
    m = json.loads((a.data_dir/"manifest.json").read_text())
    if (digest(a.queue) != config["queueSha256"] or digest(a.decoder) != config["decoderSha256"]
            or digest(a.data_dir/"decoded-transactions.jsonl") != m["decodedSha256"]):
        raise ValueError("saved queue, decoder or ledger hash mismatch")
    pending_selection="explicit-pending-ID-serialization-only-canonicality-and-height-unverified"
    if a.pending_ids != (config["selection"]==pending_selection):raise ValueError("audit mode disagrees with frozen collector scope")
    selector=selected_pending_queue if a.pending_ids else selected_queue
    rows = selector([json.loads(l) for l in a.queue.read_text().splitlines()])
    queue = {r["txid"]: r for r in rows}
    batches = {tuple(r["txid"] for r in rows[i:i+config["batchSize"]]) for i in range(0,len(rows),config["batchSize"])}
    source, envelopes = {}, []
    for path in sorted((a.data_dir/"http-responses").glob("*.json")):
        env = json.loads(path.read_text())
        body = env.get("request")
        wanted = tuple((body or {}).get("txids") or [])
        if (env.get("url") != API or wanted not in batches or env.get("httpStatus") != 200
                or hashlib.sha256(env["rawUtf8"].encode()).hexdigest() != env["responseBytesSha256"]
                or json.loads(env["rawUtf8"]) != env["response"]):
            raise ValueError("raw batch envelope/request/original bytes disagreement")
        raw, failed = validate_batch(env["response"], list(wanted))
        if set(source) & set(raw): raise ValueError("overlapping batch raw source")
        source.update(raw)
        envelopes.append({"path": str(path.resolve()), "sha256": digest(path), "transactions": len(raw), "failed": len(failed)})
    process = subprocess.Popen([str(a.decoder.resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    n = positive = opaque = 0
    seen = set()
    try:
        for line in (a.data_dir/"decoded-transactions.jsonl").read_text().splitlines():
            saved = json.loads(line); h = saved["txid"]
            if h in seen or h not in queue or h not in source: raise ValueError("duplicate/out-of-scope/missing raw source")
            seen.add(h); r = queue[h]
            if a.pending_ids:
                if saved.get("pendingRequestProvenance")!=r or saved.get("isCanonical") is not None or saved.get("blockHeight") is not None or saved.get("blockTime") is not None:
                    raise ValueError("pending request binding mismatch or invented block metadata")
            else:
                summary = Path(saved["summaryCacheFile"])
                if digest(summary) != saved["summaryCacheSha256"]: raise ValueError("metadata file hash disagreement")
                detail = cache_detail(a.summary_cache, h)
                if detail.get("txid") != h or detail.get("isCanonical") is not True or int(detail["blockHeight"]) != int(r["blockHeight"]):
                    raise ValueError("metadata identity/canonicality/height disagreement")
            raw = source[h]["hex"]
            if hashlib.sha256(bytes.fromhex(raw)).hexdigest() != saved["rawHexSha256"]: raise ValueError("serialized raw byte hash disagreement")
            addresses=({r["requestedReceiver"]} if a.pending_ids and str(r.get("requestedReceiver","")).startswith("u1") else
                {str(l["recipient"]) for l in r.get("routes", []) if str(l.get("recipient", "")).startswith("u1")})
            packet = {"hex": raw, "expectedTxid": h, "blockHeight": None if a.pending_ids else r["blockHeight"],
                      "blockTime": None if a.pending_ids else r.get("blockTime"),"isCanonical":None if a.pending_ids else True,
                      "allowV4Transparent":a.pending_ids,"unifiedAddresses":sorted(addresses)}
            process.stdin.write(json.dumps(packet)+"\n"); process.stdin.flush()
            decoded = json.loads(process.stdout.readline())
            calculated = {k:v for k,v in saved.items() if k not in ("rawHexSha256", "rawSourceEndpoint", "summaryCacheFile", "summaryCacheSha256","pendingRequestProvenance","eligibilityWarning")}
            if decoded != calculated: raise ValueError("full deterministic decoder replay disagreement: "+h)
            n += 1
            outputs = decoded.get("outputs") or []
            positive += sum(o.get("recovered") is True and int(o.get("valueZat") or 0)>0 for o in outputs)
            opaque += sum(o.get("recovered") is not True for o in outputs)
            if n%1000 == 0: print(f"offline verified={n}/{len(queue)} positiveNotes={positive}", flush=True)
    finally:
        process.stdin.close(); process.wait(timeout=30)
    result = {"challengeSolved": False, "offlineFullDecodedReplayMatches": True, "decodedTransactions": n,
              "queueTransactions": len(queue), "allScopedTransactionsDecoded": seen == set(queue), "positiveRecoveredNotes": positive,
              "opaqueOutputActions": opaque, "originalBatchEnvelopes": envelopes, "newHttpCalls": 0,
              "ledgerSha256": digest(a.data_dir/"decoded-transactions.jsonl"), "decoderSha256": digest(a.decoder),
              "queueSha256": digest(a.queue), "scriptSha256": digest(Path(__file__)),
              "scope":config["selection"],
              "warning": "Reproducible decoding/indexer claims, not independent chain consensus, note availability or target nullifier linkage."}
    dump(a.data_dir/"offline-audit.json", result)
    print(json.dumps({k:v for k,v in result.items() if k != "originalBatchEnvelopes"}), flush=True)


if __name__ == "__main__": main()
