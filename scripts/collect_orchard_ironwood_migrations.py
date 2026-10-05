#!/usr/bin/env python3
"""Enumerate and enrich every Orchard -> Ironwood migration before a target anchor.

The compact-block endpoint exposes transaction hashes and action pool names but
not public value balances.  This collector therefore works in two restartable
passes:

1. download and retain every compact block response in the requested range;
2. identify every transaction containing both Orchard and Ironwood actions,
   then cache its full CipherScan transaction summary.

No amount filter is applied while collecting.  The generated report ranks
crossings relative to the Challenge 7 net Ironwood outflow, but preserves all
mixed-pool transactions for audit.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import http.client
import json
import random
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCAN_API = "https://api.mainnet.cipherscan.app/api/lightwalletd/scan"
TX_API = "https://api.mainnet.cipherscan.app/api/tx"

IRONWOOD_ACTIVATION = 3_428_143
TARGET_ANCHOR_HEIGHT = 3_488_703
TARGET_NET_OUTFLOW_ZAT = 3_954_182
TARGET_EXIT_TIME = "2026-09-19T10:01:11Z"


def atomic_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(value)
        temporary = Path(handle.name)
    temporary.replace(path)


def dump_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def request_json(
    url: str,
    *,
    body: dict[str, Any] | None,
    timeout: float,
    attempts: int,
) -> Any:
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "User-Agent": "l2beat-privacy-hunt-research/1.0",
    }
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    errors: list[str] = []
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, data=encoded, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
            return json.loads(payload)
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:
            if isinstance(exc, urllib.error.HTTPError) and exc.code not in (429, 500, 502, 503, 504):
                raise RuntimeError(f"request failed for {url}: HTTP {exc.code}") from exc
            errors.append(f"attempt {attempt}: {exc}")
            if attempt < attempts:
                time.sleep(min(90.0, 2 ** (attempt - 1) * 2.0) + random.random())
    raise RuntimeError(f"request failed for {url}: {'; '.join(errors)}")


def load_or_fetch_chunk(
    path: Path,
    start: int,
    end: int,
    *,
    timeout: float,
    attempts: int,
) -> dict[str, Any]:
    if path.exists() and path.stat().st_size:
        return json.loads(path.read_text(encoding="utf-8"))
    payload = request_json(
        SCAN_API,
        body={"startHeight": start, "endHeight": end},
        timeout=timeout,
        attempts=attempts,
    )
    dump_json(path, payload)
    return payload


def normalize_hash(value: Any) -> str:
    text = str(value or "").lower()
    compact_order = text.removeprefix("0x")
    if len(compact_order) != 64:
        raise ValueError(f"unexpected compact transaction hash: {text!r}")
    # lightwalletd serializes hashes in internal byte order. CipherScan's
    # /api/tx endpoint and human-facing explorers use display byte order.
    return bytes.fromhex(compact_order)[::-1].hex()


def action_summary(action: dict[str, Any]) -> dict[str, Any]:
    return {
        key: action.get(key)
        for key in (
            "pool",
            "nullifier",
            "cmx",
            "ephemeralKey",
            "ciphertext",
        )
        if action.get(key) is not None
    }


def compact_records(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    all_records: list[dict[str, Any]] = []
    mixed_records: list[dict[str, Any]] = []
    for block in payload.get("blocks", []):
        height = int(block["height"])
        for tx in block.get("vtx", []):
            actions = [action_summary(action) for action in tx.get("actions", [])]
            orchard = sum(action.get("pool") == "orchard" for action in actions)
            ironwood = sum(action.get("pool") == "ironwood" for action in actions)
            record = {
                "height": height,
                "txid": normalize_hash(tx.get("hash")),
                "orchardActions": orchard,
                "ironwoodActions": ironwood,
                "actions": actions,
            }
            all_records.append(record)
            if orchard and ironwood:
                mixed_records.append(record)
    return all_records, mixed_records


def integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def timestamp(value: Any) -> str | None:
    raw = integer(value)
    if raw is None:
        return None
    return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def enrich_record(compact: dict[str, Any], tx: dict[str, Any]) -> dict[str, Any]:
    orchard_balance = integer(tx.get("valueBalanceOrchardZat"))
    ironwood_balance = integer(tx.get("valueBalanceIronwoodZat"))
    # Positive means value leaves a shielded pool; negative means it enters.
    orchard_out = max(orchard_balance or 0, 0)
    ironwood_in = max(-(ironwood_balance or 0), 0)
    delta = ironwood_in - TARGET_NET_OUTFLOW_ZAT
    if delta == 0:
        tier = "exact"
    elif 0 < delta <= 100_000:
        tier = "small-change"
    elif 100_000 < delta <= 1_000_000:
        tier = "moderate-change"
    elif delta > 1_000_000:
        tier = "large-crossing"
    else:
        tier = "below-target"
    return {
        **compact,
        "blockTime": timestamp(tx.get("blockTime")),
        "valueBalanceOrchardZat": orchard_balance,
        "valueBalanceIronwoodZat": ironwood_balance,
        "orchardValueLeavingZat": orchard_out,
        "ironwoodValueEnteringZat": ironwood_in,
        "feeZat": integer(tx.get("feeZat")),
        "transparentInputZat": integer(tx.get("totalInputZat")),
        "transparentOutputZat": integer(tx.get("totalOutputZat")),
        "version": tx.get("version"),
        "locktime": tx.get("locktime"),
        "expiryHeight": integer(tx.get("expiryHeight")),
        "zip318": tx.get("zip318"),
        "targetDeltaZat": delta,
        "targetTier": tier,
        "targetCompatibleAsSingleNote": ironwood_in >= TARGET_NET_OUTFLOW_ZAT,
        "cipherscanUrl": f"https://cipherscan.app/tx/{compact['txid']}",
    }


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    atomic_write(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in records))


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fields = [
        "height",
        "blockTime",
        "txid",
        "orchardActions",
        "ironwoodActions",
        "valueBalanceOrchardZat",
        "valueBalanceIronwoodZat",
        "orchardValueLeavingZat",
        "ironwoodValueEnteringZat",
        "feeZat",
        "targetDeltaZat",
        "targetTier",
        "targetCompatibleAsSingleNote",
        "cipherscanUrl",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
        temporary = Path(handle.name)
    temporary.replace(path)


def report_text(
    args: argparse.Namespace,
    all_records: list[dict[str, Any]],
    mixed: list[dict[str, Any]],
    enriched: list[dict[str, Any]],
) -> str:
    actual_crossings = [row for row in enriched if row["ironwoodValueEnteringZat"] > 0]
    compatible = [row for row in actual_crossings if row["targetCompatibleAsSingleNote"]]
    ranked = sorted(
        compatible,
        key=lambda row: (row["targetDeltaZat"], -row["height"]),
    )
    lines = [
        "# Orchard to Ironwood migration scan",
        "",
        f"- Block range: `{args.start:,}` through `{args.end:,}` (inclusive)",
        f"- Compact transactions retained: `{len(all_records):,}`",
        f"- Transactions containing both pools: `{len(mixed):,}`",
        f"- Enriched mixed-pool transactions: `{len(enriched):,}`",
        f"- Actual Orchard-to-Ironwood crossings: `{len(actual_crossings):,}`",
        f"- Crossings at least `{TARGET_NET_OUTFLOW_ZAT:,}` zats: `{len(compatible):,}`",
        f"- Target exit time: `{TARGET_EXIT_TIME}`",
        "",
        "No amount filter was applied during collection. `targetDeltaZat` is only a ranking",
        "feature; negative rows remain in the raw and tabular outputs because multiple notes",
        "could theoretically be combined.",
        "",
        "## Closest single-crossing candidates",
        "",
        "| Time | Height | Ironwood in | Delta | Tx |",
        "|---|---:|---:|---:|---|",
    ]
    for row in ranked[:100]:
        lines.append(
            "| {time} | {height:,} | {amount:,} | {delta:+,} | "
            "[`{short}…`]({url}) |".format(
                time=row.get("blockTime") or "unknown",
                height=row["height"],
                amount=row["ironwoodValueEnteringZat"],
                delta=row["targetDeltaZat"],
                short=row["txid"][:12],
                url=row["cipherscanUrl"],
            )
        )
    if not ranked:
        lines.append("| — | — | — | — | No compatible crossing found |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("challenge7-migration-data"))
    parser.add_argument("--start", type=int, default=IRONWOOD_ACTIVATION)
    parser.add_argument("--end", type=int, default=TARGET_ANCHOR_HEIGHT)
    parser.add_argument("--chunk", type=int, default=2_000)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--compact-only",
        action="store_true",
        help="Download/process every compact block but do not fetch full transaction summaries.",
    )
    args = parser.parse_args()
    if args.start > args.end:
        parser.error("--start must not exceed --end")
    if args.chunk < 1:
        parser.error("--chunk must be positive")
    if args.workers < 1:
        parser.error("--workers must be positive")

    output = args.output_dir
    compact_dir = output / "compact"
    tx_dir = output / "transactions"
    compact_dir.mkdir(parents=True, exist_ok=True)
    tx_dir.mkdir(parents=True, exist_ok=True)

    all_records: list[dict[str, Any]] = []
    mixed_by_txid: dict[str, dict[str, Any]] = {}
    for start in range(args.start, args.end + 1, args.chunk):
        end = min(args.end, start + args.chunk - 1)
        chunk_path = compact_dir / f"{start:07d}-{end:07d}.json"
        payload = load_or_fetch_chunk(
            chunk_path,
            start,
            end,
            timeout=args.timeout,
            attempts=args.attempts,
        )
        block_heights = {int(block["height"]) for block in payload.get("blocks", [])}
        expected = set(range(start, end + 1))
        if block_heights != expected:
            missing = sorted(expected - block_heights)
            raise RuntimeError(f"compact response {start}..{end} omitted blocks: {missing[:20]}")
        chunk_records, chunk_mixed = compact_records(payload)
        all_records.extend(chunk_records)
        for record in chunk_mixed:
            mixed_by_txid[record["txid"]] = record
        print(
            f"compact blocks={start}..{end} transactions={len(chunk_records)} "
            f"mixed={len(chunk_mixed)} total_mixed={len(mixed_by_txid)}",
            flush=True,
        )
        time.sleep(args.delay)

    all_records.sort(key=lambda row: (row["height"], row["txid"]))
    mixed = sorted(mixed_by_txid.values(), key=lambda row: (row["height"], row["txid"]))
    write_jsonl(output / "all-compact-transactions.jsonl", all_records)
    write_jsonl(output / "mixed-pool-transactions.jsonl", mixed)
    dump_json(
        output / "config.json",
        {
            "start": args.start,
            "end": args.end,
            "chunk": args.chunk,
            "targetNetOutflowZat": TARGET_NET_OUTFLOW_ZAT,
            "targetExitTime": TARGET_EXIT_TIME,
            "compactTransactionCount": len(all_records),
            "mixedPoolTransactionCount": len(mixed),
        },
    )

    enriched: list[dict[str, Any]] = []
    if not args.compact_only:
        def fetch_enriched(compact: dict[str, Any]) -> dict[str, Any]:
            txid = compact["txid"]
            tx_path = tx_dir / f"{txid}.json"
            if tx_path.exists() and tx_path.stat().st_size:
                tx = json.loads(tx_path.read_text(encoding="utf-8"))
            else:
                tx = request_json(
                    f"{TX_API}/{txid}",
                    body=None,
                    timeout=args.timeout,
                    attempts=args.attempts,
                )
                dump_json(tx_path, tx)
                time.sleep(args.delay)
            return enrich_record(compact, tx)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            for index, row in enumerate(executor.map(fetch_enriched, mixed), start=1):
                enriched.append(row)
                if index % 100 == 0 or index == len(mixed):
                    print(f"enriched={index}/{len(mixed)}", flush=True)

    write_jsonl(output / "migrations.jsonl", enriched)
    write_csv(output / "migrations.csv", enriched)
    atomic_write(output / "report.md", report_text(args, all_records, mixed, enriched))
    print(f"done output={output} mixed={len(mixed)} enriched={len(enriched)}", flush=True)


if __name__ == "__main__":
    main()
