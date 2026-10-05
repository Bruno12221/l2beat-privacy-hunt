#!/usr/bin/env python3
"""Rank structurally possible Challenge 7 one- and two-note inputs.

The target transaction removes 3,954,182 zatoshis from Ironwood and has two
Ironwood actions. It can therefore consume one or two real notes. This script
combines the public NEAR Intents route inventory with every available
CipherScan payout summary, searches singles and pairs, and writes an auditable
report.

Important distinctions:

* A decoded NEAR bridge payout is a note candidate. The bridge's zero OVK lets
  its recipient and output value be recovered.
* An Orchard -> Ironwood value balance is only a migration budget. A migration
  can create multiple Ironwood outputs, whose individual values are hidden.
  Migration budgets are ranked separately and are never silently treated as
  exact notes.
* Routes without a fetched payout summary use the explorer's reported output
  as an estimate. Results containing one are explicitly labelled estimated.

The current-data run is intentionally useful before the complete collector is
finished. Re-run it with the collector's payout-summaries JSONL for the final
search.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import json
import math
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TARGET_ZAT = 3_954_182
TARGET_EXIT_TIME = "2026-09-19T10:01:11Z"
TARGET_ANCHOR_HEIGHT = 3_488_703
IRONWOOD_ACTIVATION_TIME = "2026-07-28T14:07:23Z"


def utc(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def first(items: Any) -> str | None:
    if isinstance(items, list):
        for item in items:
            if item:
                return str(item).removeprefix("0x").lower()
    elif items:
        return str(items).removeprefix("0x").lower()
    return None


def load_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        first_char = handle.read(1)
        handle.seek(0)
        if first_char == "[":
            value = json.load(handle)
            return [row for row in value if isinstance(row, dict)]
        return [
            json.loads(line)
            for line in handle
            if line.strip()
        ]


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


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fields = [
        "rank",
        "kind",
        "valueConfidence",
        "inputCount",
        "inputTotalZat",
        "possibleChangeZat",
        "latestBlockTime",
        "hoursBeforeExit",
        "sameRecipient",
        "sameSourceSender",
        "sameRefundAddress",
        "sameReferral",
        "sharedRecipient",
        "sharedSourceSenders",
        "sharedRefundAddress",
        "sharedReferral",
        "note1ValueZat",
        "note1Txid",
        "note1SourceSenders",
        "note1Recipient",
        "note2ValueZat",
        "note2Txid",
        "note2SourceSenders",
        "note2Recipient",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            cooked = dict(record)
            for field in ("sharedSourceSenders", "note1SourceSenders", "note2SourceSenders"):
                if isinstance(cooked.get(field), list):
                    cooked[field] = ";".join(str(value) for value in cooked[field])
            writer.writerow(cooked)
        temporary = Path(handle.name)
    temporary.replace(path)


def route_txid(route: dict[str, Any]) -> str | None:
    return first(route.get("destinationChainTxHashes")) or first(route.get("zcashPayoutTxid"))


def route_key(route: dict[str, Any]) -> str:
    txid = route_txid(route)
    if txid:
        return txid
    return "|".join(
        str(route.get(key) or "")
        for key in ("depositAddress", "depositMemo", "createdAt")
    )


def reported_value(route: dict[str, Any]) -> int | None:
    value = integer(route.get("amountOut")) or integer(route.get("rawAmountOut"))
    if value is not None:
        return value
    try:
        return round(float(route["amountOutFormatted"]) * 100_000_000)
    except (KeyError, TypeError, ValueError):
        return None


def normalized_senders(route: dict[str, Any]) -> list[str]:
    values = route.get("sourceSenders") or route.get("senders") or []
    if not isinstance(values, list):
        values = [values]
    return sorted({str(value).lower() for value in values if value})


def meaningful_refund(value: Any) -> str | None:
    if not value:
        return None
    normalized = str(value).lower()
    # Intents uses null/sentinel EVM refund addresses for routes where no
    # user-controlled refund address was supplied. Sharing one is service
    # plumbing, not a wallet-control signal.
    if normalized in {
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000001",
    }:
        return None
    return str(value)


def summary_value(summary: dict[str, Any]) -> int | None:
    for field in (
        "actualIronwoodValueCreatedZat",
        "actualShieldedNoteZat",
    ):
        value = integer(summary.get(field))
        if value and value > 0:
            return value
    balance = integer(summary.get("valueBalanceIronwoodZat"))
    if balance is not None and balance < 0:
        return -balance
    return None


def block_time(summary: dict[str, Any], route: dict[str, Any]) -> str | None:
    value = summary.get("blockTime")
    if value:
        return str(value)
    epoch = integer(summary.get("zcashBlockTime"))
    if epoch is not None:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return str(route.get("createdAt")) if route.get("createdAt") else None


def make_note(
    route: dict[str, Any], summary: dict[str, Any] | None, activation: datetime
) -> dict[str, Any] | None:
    created = str(route.get("createdAt") or "")
    if not created or utc(created) < activation:
        return None

    summary_fetched = summary is not None
    summary = summary or {}
    exact = summary_value(summary)
    # Once a Zcash transaction has been fetched, a zero/non-negative Ironwood
    # balance means this route did not create an Ironwood note (for example it
    # paid a transparent t-address). Do not fall back to the explorer amount.
    if summary_fetched and exact is None and any(
        key in summary
        for key in (
            "actualIronwoodValueCreatedZat",
            "actualShieldedNoteZat",
            "valueBalanceIronwoodZat",
            "ironwoodValueBalanceZat",
        )
    ):
        return None
    estimate = reported_value(route)
    value = exact if exact is not None else estimate
    if value is None or value <= 0:
        return None

    height = integer(summary.get("zcashBlockHeight")) or integer(summary.get("blockHeight"))
    when = block_time(summary, route)
    return {
        "id": route_key(route),
        "kind": "direct-near-payout",
        "valueZat": value,
        "valueConfidence": "exact-public-balance" if exact is not None else "explorer-estimate",
        "anchorVerified": height is not None,
        "anchorEligible": height is None or height <= TARGET_ANCHOR_HEIGHT,
        "zcashBlockHeight": height,
        "blockTime": when,
        "createdAt": created,
        "zcashPayoutTxid": route_txid(route),
        "recipient": summary.get("recipient") or route.get("recipient"),
        "sourceSenders": normalized_senders({**route, **summary}),
        "sourceTxHash": summary.get("sourceTxHash") or first(route.get("originChainTxHashes")),
        "refundAddress": meaningful_refund(
            route.get("refundTo") or summary.get("refundAddress")
        ),
        "referral": summary.get("referral") or route.get("referral"),
        "originAsset": summary.get("originAsset") or route.get("originAsset"),
        "depositAddress": summary.get("depositAddress") or route.get("depositAddress"),
        "reportedValueZat": estimate,
    }


def latest_time(notes: list[dict[str, Any]]) -> str | None:
    values = [str(note.get("blockTime")) for note in notes if note.get("blockTime")]
    return max(values) if values else None


def hours_before(value: str | None, target_time: datetime) -> float | None:
    if not value:
        return None
    return (target_time - utc(value)).total_seconds() / 3600


def shared_value(notes: list[dict[str, Any]], field: str) -> str | None:
    values = {str(note.get(field)).lower() for note in notes if note.get(field)}
    return next(iter(values)) if len(values) == 1 else None


def shared_senders(notes: list[dict[str, Any]]) -> list[str]:
    if not notes:
        return []
    sets = [set(note.get("sourceSenders") or []) for note in notes]
    return sorted(set.intersection(*sets)) if sets else []


def candidate_record(notes: list[dict[str, Any]], target: int, target_time: datetime) -> dict[str, Any]:
    total = sum(int(note["valueZat"]) for note in notes)
    recipient = shared_value(notes, "recipient")
    refund = shared_value(notes, "refundAddress")
    referral = shared_value(notes, "referral")
    senders = shared_senders(notes)
    when = latest_time(notes)
    confidence = (
        "exact"
        if all(note["valueConfidence"] == "exact-public-balance" for note in notes)
        else "contains-estimate"
    )
    result: dict[str, Any] = {
        "kind": "single" if len(notes) == 1 else "pair",
        "valueConfidence": confidence,
        "inputCount": len(notes),
        "inputTotalZat": total,
        "possibleChangeZat": total - target,
        "latestBlockTime": when,
        "hoursBeforeExit": hours_before(when, target_time),
        "sameRecipient": bool(recipient) if len(notes) > 1 else None,
        "sameSourceSender": bool(senders) if len(notes) > 1 else None,
        "sameRefundAddress": bool(refund) if len(notes) > 1 else None,
        "sameReferral": bool(referral) if len(notes) > 1 else None,
        "sharedRecipient": recipient,
        "sharedSourceSenders": senders,
        "sharedRefundAddress": refund,
        "sharedReferral": referral,
        "notes": notes,
    }
    for index, note in enumerate(notes, start=1):
        result[f"note{index}ValueZat"] = note["valueZat"]
        result[f"note{index}Txid"] = note.get("zcashPayoutTxid")
        result[f"note{index}SourceSenders"] = note.get("sourceSenders") or []
        result[f"note{index}Recipient"] = note.get("recipient")
    return result


def pair_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return (
        record["possibleChangeZat"],
        record["valueConfidence"] != "exact",
        not record.get("sameRecipient"),
        not record.get("sameSourceSender"),
        not record.get("sameRefundAddress"),
        record.get("hoursBeforeExit") is None,
        record.get("hoursBeforeExit") or math.inf,
    )


def closest_pairs(
    notes: list[dict[str, Any]], target: int, target_time: datetime, top: int
) -> list[dict[str, Any]]:
    """Return low-change pairs without materializing the O(n^2) product."""
    ordered = sorted(notes, key=lambda note: (note["valueZat"], note["id"]))
    values = [int(note["valueZat"]) for note in ordered]
    found: dict[tuple[str, str], dict[str, Any]] = {}
    # For each left note, the first few right notes above the target threshold
    # contain all locally minimal-change options. Keeping four protects against
    # duplicate values and later cluster sorting without exploding output.
    for left_index, left in enumerate(ordered):
        minimum = max(left_index + 1, bisect.bisect_left(values, target - values[left_index]))
        for right_index in range(minimum, min(len(ordered), minimum + 4)):
            right = ordered[right_index]
            if left["id"] == right["id"]:
                continue
            key = tuple(sorted((str(left["id"]), str(right["id"]))))
            found[key] = candidate_record([left, right], target, target_time)
    return sorted(found.values(), key=pair_sort_key)[:top]


def clustered_pairs(
    notes: list[dict[str, Any]], target: int, target_time: datetime, top: int
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for note in notes:
        if note.get("recipient"):
            groups[("recipient", str(note["recipient"]).lower())].append(note)
        for sender in note.get("sourceSenders") or []:
            groups[("source", str(sender).lower())].append(note)
        if note.get("refundAddress"):
            groups[("refund", str(note["refundAddress"]).lower())].append(note)

    found: dict[tuple[str, str], dict[str, Any]] = {}
    for group_notes in groups.values():
        if len(group_notes) < 2:
            continue
        for record in closest_pairs(group_notes, target, target_time, top=10):
            ids = tuple(sorted(str(note["id"]) for note in record["notes"]))
            found[ids] = record
    return sorted(found.values(), key=pair_sort_key)[:top]


def migration_budgets(
    migrations: Iterable[dict[str, Any]], target: int, target_time: datetime
) -> list[dict[str, Any]]:
    results = []
    for row in migrations:
        value = integer(row.get("ironwoodValueEnteringZat")) or 0
        height = integer(row.get("height"))
        if value < target or (height is not None and height > TARGET_ANCHOR_HEIGHT):
            continue
        when = str(row.get("blockTime")) if row.get("blockTime") else None
        results.append(
            {
                "kind": "migration-budget",
                "txid": row.get("txid"),
                "height": height,
                "blockTime": when,
                "hoursBeforeExit": hours_before(when, target_time),
                "ironwoodValueEnteringZat": value,
                "possibleBudgetRemainderZat": value - target,
                "ironwoodActions": integer(row.get("ironwoodActions")),
                "warning": (
                    "Public total across Ironwood outputs; individual note values are hidden."
                ),
                "cipherscanUrl": row.get("cipherscanUrl"),
            }
        )
    return sorted(
        results,
        key=lambda row: (
            row["possibleBudgetRemainderZat"],
            row.get("hoursBeforeExit") or math.inf,
        ),
    )


def compact_source(record: dict[str, Any]) -> str:
    notes = record.get("notes") or []
    sources = sorted(
        {
            sender
            for note in notes
            for sender in note.get("sourceSenders") or []
        }
    )
    return ", ".join(sources) if sources else "—"


def report_text(
    target: int,
    routes_count: int,
    notes: list[dict[str, Any]],
    exact_notes: list[dict[str, Any]],
    singles: list[dict[str, Any]],
    cluster_pairs: list[dict[str, Any]],
    global_pairs: list[dict[str, Any]],
    budgets: list[dict[str, Any]],
) -> str:
    estimated = sum(note["valueConfidence"] == "explorer-estimate" for note in notes)
    unverified = sum(not note["anchorVerified"] for note in notes)
    lines = [
        "# Challenge 7 one/two-note budget search",
        "",
        f"- Target Ironwood outflow: `{target:,}` zats",
        f"- Explorer routes read: `{routes_count:,}`",
        f"- Post-activation direct payout candidates: `{len(notes):,}`",
        f"- Exact public-balance values: `{len(exact_notes):,}`",
        f"- Explorer-estimated values: `{estimated:,}`",
        f"- Candidates without a fetched Zcash height: `{unverified:,}`",
        f"- Compatible migration budgets: `{len(budgets):,}`",
        "",
        "This is a current-data pass. Rows containing explorer estimates must be rerun after the",
        "filter-free payout collector completes. A migration balance is a public budget across",
        "one or more hidden outputs, not proof of one note.",
        "",
        "## Closest single-note candidates",
        "",
        "| Confidence | Value | Change | Hours | Receiver | Source | Zcash tx |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for row in singles[:40]:
        note = row["notes"][0]
        txid = note.get("zcashPayoutTxid") or "—"
        link = f"[{txid[:12]}…](https://cipherscan.app/tx/{txid})" if txid != "—" else "—"
        recipient = str(note.get("recipient") or "—")
        if len(recipient) > 20:
            recipient = recipient[:17] + "…"
        hours = row.get("hoursBeforeExit")
        lines.append(
            f"| {row['valueConfidence']} | {row['inputTotalZat']:,} | "
            f"{row['possibleChangeZat']:,} | {hours:.2f} | `{recipient}` | "
            f"`{compact_source(row)}` | {link} |"
            if hours is not None
            else f"| {row['valueConfidence']} | {row['inputTotalZat']:,} | "
            f"{row['possibleChangeZat']:,} | — | `{recipient}` | "
            f"`{compact_source(row)}` | {link} |"
        )

    lines += [
        "",
        "## Closest clustered two-note candidates",
        "",
        "Pairs here share a decoded receiver, source sender or refund address. This is the",
        "highest-value pair cohort, but shared use of a service is not automatically common control.",
        "",
        "| Confidence | Total | Change | Hours | Shared evidence | Source(s) | Zcash txs |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for row in cluster_pairs[:40]:
        evidence = []
        if row.get("sameRecipient"):
            evidence.append("receiver")
        if row.get("sameSourceSender"):
            evidence.append("source")
        if row.get("sameRefundAddress"):
            evidence.append("refund")
        txids = [str(note.get("zcashPayoutTxid") or "—") for note in row["notes"]]
        tx_text = ", ".join(txid[:10] + "…" for txid in txids)
        hours = row.get("hoursBeforeExit")
        hours_text = f"{hours:.2f}" if hours is not None else "—"
        lines.append(
            f"| {row['valueConfidence']} | {row['inputTotalZat']:,} | "
            f"{row['possibleChangeZat']:,} | {hours_text} | {', '.join(evidence) or '—'} | "
            f"`{compact_source(row)}` | `{tx_text}` |"
        )

    lines += [
        "",
        "## Closest global two-note coincidences",
        "",
        "These pairs need not belong to one wallet. They are retained to measure the base rate,",
        "not as attribution candidates by themselves.",
        "",
        "| Confidence | Total | Change | Hours | Source(s) | Zcash txs |",
        "|---|---:|---:|---:|---|---|",
    ]
    for row in global_pairs[:30]:
        txids = [str(note.get("zcashPayoutTxid") or "—") for note in row["notes"]]
        tx_text = ", ".join(txid[:10] + "…" for txid in txids)
        hours = row.get("hoursBeforeExit")
        hours_text = f"{hours:.2f}" if hours is not None else "—"
        lines.append(
            f"| {row['valueConfidence']} | {row['inputTotalZat']:,} | "
            f"{row['possibleChangeZat']:,} | {hours_text} | `{compact_source(row)}` | "
            f"`{tx_text}` |"
        )

    lines += [
        "",
        "## Closest Orchard→Ironwood migration budgets",
        "",
        "| Public budget | Remainder | Hours | Ironwood actions | Transaction |",
        "|---:|---:|---:|---:|---|",
    ]
    for row in budgets[:30]:
        txid = str(row.get("txid") or "")
        link = f"[{txid[:12]}…](https://cipherscan.app/tx/{txid})"
        hours = row.get("hoursBeforeExit")
        hours_text = f"{hours:.2f}" if hours is not None else "—"
        lines.append(
            f"| {row['ironwoodValueEnteringZat']:,} | "
            f"{row['possibleBudgetRemainderZat']:,} | {hours_text} | "
            f"{row.get('ironwoodActions') or '—'} | {link} |"
        )

    lines += [
        "",
        "## Interpretation",
        "",
        "A low-change row is a candidate, not a nullifier-to-note proof. Clustered exact-value",
        "pairs deserve investigation first. Estimated rows can move by bridge fees and are",
        "provisional until their Zcash transactions are fetched. Global unrelated pairs quantify",
        "how easy it is to obtain an attractive amount match by chance.",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--routes",
        type=Path,
        default=Path("challenge7-exact-link-data/all_routes.jsonl"),
    )
    parser.add_argument(
        "--summary",
        type=Path,
        action="append",
        default=[],
        help="Payout summary JSON/JSONL; repeat for multiple sources.",
    )
    parser.add_argument(
        "--migrations",
        type=Path,
        default=Path("challenge7-migration-data/migrations.jsonl"),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("challenge7-note-budget-data")
    )
    parser.add_argument("--target-zat", type=int, default=TARGET_ZAT)
    parser.add_argument("--target-exit-time", default=TARGET_EXIT_TIME)
    parser.add_argument("--activation-time", default=IRONWOOD_ACTIVATION_TIME)
    parser.add_argument("--top", type=int, default=500)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.top < 1:
        raise SystemExit("--top must be positive")
    routes = load_records(args.routes)
    summaries: dict[str, dict[str, Any]] = {}
    summary_paths = args.summary or [
        Path("challenge7-exact-link-data/candidates.json"),
        Path("challenge7-orchard-trace-data/all-payout-summaries.jsonl"),
    ]
    for path in summary_paths:
        for row in load_records(path):
            txid = first(row.get("zcashPayoutTxid"))
            if txid:
                # Prefer a row that contains an actual Ironwood value.
                previous = summaries.get(txid)
                if previous is None or summary_value(row) is not None:
                    summaries[txid] = row

    activation = utc(args.activation_time)
    notes_by_id: dict[str, dict[str, Any]] = {}
    for route in routes:
        txid = route_txid(route)
        note = make_note(route, summaries.get(txid or ""), activation)
        if note and note["anchorEligible"]:
            notes_by_id[note["id"]] = note
    notes = list(notes_by_id.values())
    exact_notes = [note for note in notes if note["valueConfidence"] == "exact-public-balance"]
    target_time = utc(args.target_exit_time)

    singles = sorted(
        (
            candidate_record([note], args.target_zat, target_time)
            for note in notes
            if note["valueZat"] >= args.target_zat
        ),
        key=lambda row: (
            row["valueConfidence"] != "exact",
            row["possibleChangeZat"],
            row.get("hoursBeforeExit") or math.inf,
        ),
    )[: args.top]
    cluster_pairs = clustered_pairs(notes, args.target_zat, target_time, args.top)
    global_pairs = closest_pairs(notes, args.target_zat, target_time, args.top)
    budgets = migration_budgets(
        load_records(args.migrations), args.target_zat, target_time
    )

    for rows in (singles, cluster_pairs, global_pairs):
        for rank, row in enumerate(rows, start=1):
            row["rank"] = rank

    output = args.output_dir
    dump_json(output / "notes.json", notes)
    dump_json(output / "single-candidates.json", singles)
    dump_json(output / "clustered-pair-candidates.json", cluster_pairs)
    dump_json(output / "global-pair-controls.json", global_pairs)
    dump_json(output / "migration-budgets.json", budgets)
    write_csv(output / "single-candidates.csv", singles)
    write_csv(output / "clustered-pair-candidates.csv", cluster_pairs)
    write_csv(output / "global-pair-controls.csv", global_pairs)
    atomic_write(
        output / "report.md",
        report_text(
            args.target_zat,
            len(routes),
            notes,
            exact_notes,
            singles,
            cluster_pairs,
            global_pairs,
            budgets,
        ),
    )
    dump_json(
        output / "config.json",
        {
            "routes": str(args.routes),
            "summaryPaths": [str(path) for path in summary_paths],
            "migrations": str(args.migrations),
            "targetZat": args.target_zat,
            "targetExitTime": args.target_exit_time,
            "activationTime": args.activation_time,
            "targetAnchorHeight": TARGET_ANCHOR_HEIGHT,
            "routeCount": len(routes),
            "noteCount": len(notes),
            "exactNoteCount": len(exact_notes),
            "estimatedNoteCount": len(notes) - len(exact_notes),
        },
    )
    print(
        f"done output={output} notes={len(notes)} exact={len(exact_notes)} "
        f"singles={len(singles)} clustered_pairs={len(cluster_pairs)} "
        f"global_controls={len(global_pairs)} migration_budgets={len(budgets)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
