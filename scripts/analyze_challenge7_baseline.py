#!/usr/bin/env python3
"""Offline, evidence-typed Challenge 7 analysis. No network calls.

Public pool balances are kept as transaction aggregates. Only independently
recovered output plaintexts enter the decoded-note search. A second search of
balances is explicitly conditional on a single-output/no-shielded-input model.
Every pair in the configured change interval is retained: no per-left/per-wallet
shortlist truncation. An upper interval is a search priority, never an exclusion
of larger-change funding histories. Existing collectors/outputs are not changed.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

TARGET = 3_954_182
ACTIVATION = 3_428_143
ANCHOR = 3_488_703
EXIT_TIME = "2026-09-19T10:01:11Z"
HEX_TXID = re.compile(r"^(?:0x)?[a-fA-F0-9]{64}$")
EVM = re.compile(r"^0x[a-fA-F0-9]{40}$")
SENTINELS = {"0x" + "0" * 40, "0x" + "0" * 39 + "1",
             "1nc1nerator11111111111111111111111111111111"}


def utc(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def integer(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def zcash_txid(value):
    value = str(value or "")
    return value.removeprefix("0x").lower() if HEX_TXID.fullmatch(value) else None


def payout_txids(route):
    values = route.get("destinationChainTxHashes") or []
    if isinstance(values, str):
        values = [values]
    if route.get("zcashPayoutTxid"):
        values = [*values, route["zcashPayoutTxid"]]
    return sorted({txid for value in values if (txid := zcash_txid(value))})


def route_class(route):
    if str(route.get("recipientType", "")).upper() == "INTENTS":
        return "internal-intents"
    return "destination-with-hash" if payout_txids(route) else "unresolved-destination"


def normalized_address(value):
    if not value:
        return None
    value = str(value)
    return value.lower() if EVM.fullmatch(value) else value


def reported_value(route):
    for name in ("amountOut", "rawAmountOut"):
        number = integer(route.get(name))
        if number is not None:
            return number
    try:
        number = Decimal(str(route["amountOutFormatted"])) * 100_000_000
        return int(number) if number == number.to_integral_value() else None
    except (KeyError, InvalidOperation, ValueError):
        return None


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    temporary.replace(path)


def dump(path, value):
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_rows(path, records):
    atomic_write(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in records))


def load(path, manifest):
    if not path.exists():
        raise FileNotFoundError(path)
    # Hash exactly the bytes parsed, including atomically replaced live files.
    payload = path.read_bytes()
    manifest[str(path.resolve())] = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
    if payload.lstrip().startswith(b"["):
        return json.loads(payload)
    return [json.loads(line) for line in payload.splitlines() if line.strip()]


def exit_note_packets(path, manifest):
    """Supplement explorer inventories with separately verified connector exits."""
    payload = path.read_bytes()
    hashed = hashlib.sha256(payload).hexdigest()
    source_manifest_path = path.parent / "manifest.json"
    source_manifest_bytes = source_manifest_path.read_bytes()
    source_manifest = json.loads(source_manifest_bytes)
    source = json.loads(payload)
    if source_manifest.get("stopped") or source_manifest.get("analysisSha256") != hashed or not source.get("modernAuditComplete"):
        raise ValueError("completed hash-matching connector-exit analysis required")
    manifest[str(path.resolve())] = {"sha256": hashed, "bytes": len(payload)}
    manifest[str(source_manifest_path.resolve())] = {"sha256": hashlib.sha256(source_manifest_bytes).hexdigest(), "bytes": len(source_manifest_bytes)}
    packets = []
    provenance = {}
    for exit in source["modernExits"]:
        if "payout" not in exit: continue
        if not exit.get("publicExecutionVerified") or not exit.get("rawComparison", {}).get("verified"):
            raise ValueError("supplemental payout missing actual execution/serialized packet checks")
        decoded = dict(exit["payout"]["decoded"])
        # Account-exit decodes preserve the API's exact Unix-seconds clock;
        # the baseline works with explicit ISO UTC. Normalize the declared unit,
        # never interpret arbitrary floats or nanoseconds as a second timestamp.
        clock = decoded.get("blockTime")
        if isinstance(clock, int) and not isinstance(clock, bool) or isinstance(clock, str) and clock.isdigit():
            if not 0 <= int(clock) <= 9999999999:
                raise ValueError("supplemental Unix-seconds timestamp out of range")
            decoded["blockTime"] = datetime.fromtimestamp(int(clock), timezone.utc).isoformat().replace("+00:00", "Z")
        packets.append(decoded)
        provenance[decoded["txid"]] = {"nearRoot": exit["nearRoot"], "originNonce": exit["originNonce"],
              "acceptedIntentHash": exit["intentHash"], "requestedReceiver": exit["requestedReceiver"],
              "sourceAnalysis": str(path.resolve()), "executionAndPayoutPacketVerified": True,
              "warning": "Accepted request and created output, not subsequent private consumption or external funding allocation."}
    return packets, provenance


def verified_pending_packets(path, raw_dir, manifest):
    """Replay complete enriched metadata against the frozen raw ledger offline."""
    from enrich_challenge7_pending_notes import API, enrich, ironwood_queue, validate_envelope
    def read_json(source):
        payload=source.read_bytes()
        manifest[str(source.resolve())]={"sha256":hashlib.sha256(payload).hexdigest(),"bytes":len(payload)}
        return json.loads(payload)
    completed=read_json(path.parent/"manifest.json")
    raw_manifest=read_json(raw_dir/"manifest.json")
    raw_audit=read_json(raw_dir/"offline-audit.json")
    raw_path=raw_dir/"decoded-transactions.jsonl"
    raw=load(raw_path,manifest)
    raw_hash=manifest[str(raw_path.resolve())]["sha256"]
    if (not raw_manifest.get("scopeComplete") or raw_manifest.get("decodedSha256")!=raw_hash
            or raw_audit.get("ledgerSha256")!=raw_hash or not raw_audit.get("allScopedTransactionsDecoded")
            or not raw_audit.get("offlineFullDecodedReplayMatches") or completed.get("rawLedgerSha256")!=raw_hash
            or completed.get("stopped") or completed.get("unresolvedTransactions")!=0 or completed.get("anchor")!=ANCHOR):
        raise ValueError("completed raw replay and complete hash-matching metadata scope required")
    queue=ironwood_queue(raw);by_id={r["txid"]:r for r in queue}
    results_path=path.parent/"metadata-results.jsonl"
    results=load(results_path,manifest)
    saved=load(path,manifest)
    if (manifest[str(results_path.resolve())]["sha256"]!=completed.get("metadataResultsSha256")
            or manifest[str(path.resolve())]["sha256"]!=completed.get("eligibleLedgerSha256")
            or len(results)!=len(by_id) or {r["txid"] for r in results}!=set(by_id)
            or completed.get("selectedIronwoodTransactions")!=len(by_id)
            or completed.get("metadataTransactions")!=len(by_id)):
        raise ValueError("metadata/eligible ledger hashes or complete selection disagree")
    replay=[];statuses=Counter()
    for result in results:
        if result.get("state")!="metadata":raise ValueError("unresolved metadata row")
        source=result["source"];source_path=Path(source["path"])
        if source.get("url")!=API+result["txid"]:raise ValueError("metadata source URL identity disagreement")
        envelope=read_json(source_path)
        if manifest[str(source_path.resolve())]["sha256"]!=source["sha256"] or envelope.get("httpStatus")!=200:
            raise ValueError("metadata original envelope hash/status disagreement")
        detail=validate_envelope(envelope,API+result["txid"])
        if detail!=result.get("detail"):raise ValueError("derived metadata differs from original response")
        row,status=enrich(by_id[result["txid"]],detail,source);statuses[status]+=1
        if row is not None:replay.append(row)
    replay.sort(key=lambda r:r["txid"])
    if (saved!=replay or completed.get("heightEligibleTransactions")!=len(replay)
            or completed.get("statusCounts")!=dict(statuses)):
        raise ValueError("full eligible-ledger replay or status counts disagree")
    return replay,{"allMetadataOriginalsVerified":True,"eligibleLedgerReplayMatches":True,
                   "selectedTransactions":len(by_id),"eligibleTransactions":len(replay),
                   "statusCounts":dict(statuses),"newHttpCalls":0}


def packet_metadata(packet, summary, canonical_by_txid, txid):
    """Explicitly verified metadata cannot silently inherit stale summaries."""
    if packet.get("canonicalMetadataSource"):
        height=integer(packet.get("blockHeight"));time=packet.get("blockTime")
        if packet.get("isCanonical") is not True or not packet.get("canonicalBlockHash") or height is None or not time:
            raise ValueError("enriched packet lacks verified block identity")
        old_height=integer(summary.get("zcashBlockHeight"));old_time=summary.get("blockTime")
        if (old_height is not None and old_height!=height or old_time and utc(old_time)!=utc(time)
                or canonical_by_txid.get(txid) is False):
            raise ValueError("enriched metadata conflicts with existing canonical summary")
        return height,time,True
    return (integer(summary.get("zcashBlockHeight")) or integer(packet.get("blockHeight")),
            summary.get("blockTime") or packet.get("blockTime"),
            canonical_by_txid.get(txid,packet.get("isCanonical")))


def route_link(route):
    senders = route.get("senders") or route.get("sourceSenders") or []
    if isinstance(senders, str):
        senders = [senders]
    refund = normalized_address(route.get("refundTo") or route.get("refundAddress"))
    if refund in SENTINELS:
        refund = None
    origin_hashes = route.get("originChainTxHashes") or []
    if isinstance(origin_hashes, str):
        origin_hashes = [origin_hashes]
    return {
        "createdAt": route.get("createdAt"), "depositAddress": route.get("depositAddress"),
        "depositMemo": route.get("depositMemo"), "recipient": route.get("recipient"),
        "recipientType": route.get("recipientType"), "originAsset": route.get("originAsset"),
        "sourceSenders": sorted({normalized_address(x) for x in senders if x}),
        "sourceTxHashes": origin_hashes, "nearTxHashes": route.get("nearTxHashes") or [],
        "refundAddress": refund, "referral": route.get("referral"),
        "reportedAmountOutZat": reported_value(route),
    }


def common_values(left, right):
    # An absent value on either side never becomes a match.
    if not left or not right:
        return []
    return sorted(set(left) & set(right))


def metadata(links):
    return {
        "sourceSenders": sorted({x for link in links for x in link["sourceSenders"]}),
        "refundAddresses": sorted({link["refundAddress"] for link in links if link["refundAddress"]}),
        "recipients": sorted({str(link["recipient"]) for link in links if link["recipient"]}),
        "referrals": sorted({str(link["referral"]) for link in links if link["referral"]}),
        "routeLinkCount": len(links), "routeAttributionAmbiguous": len(links) > 1,
    }


def cache_detail(cache, txid):
    url = "https://api.mainnet.cipherscan.app/api/tx/" + txid
    name = hashlib.sha256(url.encode()).hexdigest() + ".json"
    path = cache / name
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def eligibility(height, canonical, block_time=None):
    if canonical is False:
        return "noncanonical"
    if height is None:
        return "height-unverified"
    if height < ACTIVATION:
        return "before-activation"
    if height > ANCHOR:
        return "after-anchor"
    if block_time and utc(block_time) > utc(EXIT_TIME):
        return "time-height-conflict"
    return "height-compatible" if canonical is True else "canonical-unverified"


def balance_record(summary, links, detail):
    txid = zcash_txid(summary.get("zcashPayoutTxid") or summary.get("txid"))
    value = integer(summary.get("actualIronwoodValueCreatedZat"))
    if value is None:
        balance = integer(summary.get("valueBalanceIronwoodZat"))
        value = max(-balance, 0) if balance is not None else None
    if not txid or not value:
        return None
    height = integer(summary.get("zcashBlockHeight") or summary.get("blockHeight"))
    canonical = detail.get("isCanonical")
    time = summary.get("blockTime")
    return {
        "id": txid, "txid": txid, "pool": "ironwood", "valueZat": value,
        "valueConfidence": "public-net-balance-NOT-a-decoded-note",
        "blockHeight": height, "blockTime": time, "isCanonical": canonical,
        "anchorEligibility": eligibility(height, canonical, time),
        "ironwoodActions": integer(summary.get("ironwoodActions")),
        "routes": links, **metadata(links),
    }


def pair_indices(records, target, max_change):
    """All unordered pairs in [target, target + max_change], including all ties."""
    ordered = sorted(records, key=lambda row: (row["valueZat"], row["id"]))
    values = [row["valueZat"] for row in ordered]
    for i, left in enumerate(ordered):
        start = max(i + 1, bisect.bisect_left(values, target - left["valueZat"]))
        end = bisect.bisect_right(values, target + max_change - left["valueZat"])
        for j in range(start, end):
            yield left, ordered[j]


def pair_count(records, target, max_change=None):
    values = sorted(row["valueZat"] for row in records)
    count = 0
    for i, value in enumerate(values):
        start = max(i + 1, bisect.bisect_left(values, target - value))
        end = len(values) if max_change is None else max(i + 1, bisect.bisect_right(values, target + max_change - value))
        count += max(0, end - start)
    return count


def pair_record(left, right, target, conditional):
    latest = max((utc(row["blockTime"]) for row in (left, right) if row.get("blockTime")), default=None)
    same_receiver = common_values(left.get("receiverBytes", []), right.get("receiverBytes", []))
    shared = {
        name: common_values(left.get(field), right.get(field))
        for name, field in (("senders", "sourceSenders"), ("refunds", "refundAddresses"),
                            ("fullUnifiedAddresses", "recipients"), ("referrals", "referrals"))
    }
    total = left["valueZat"] + right["valueZat"]
    return {
        "leftId": left["id"], "rightId": right["id"],
        "leftTxid": left["txid"], "rightTxid": right["txid"],
        "inputTotalZat": total, "possibleChangeZat": total - target,
        "hoursBeforeExit": (utc(EXIT_TIME) - latest).total_seconds() / 3600 if latest else None,
        "shared": shared, "sameDecodedReceiver": same_receiver,
        "conditionalOnSingleOutputModel": conditional,
        "routeAttributionAmbiguous": left.get("routeAttributionAmbiguous", False) or right.get("routeAttributionAmbiguous", False),
        "warning": "Shared service senders/referrals do not establish common control; no nullifier link.",
    }


def search(records, output, target, max_change, conditional):
    # Counts cover all amount-compatible combinations, not only written intervals.
    stats = {
        "records": len(records), "singleGeTarget": sum(x["valueZat"] >= target for x in records),
        "allUnorderedPairs": len(records) * (len(records) - 1) // 2,
        "allAmountCompatiblePairs": pair_count(records, target),
        "pairMaxChangeZat": max_change,
        "pairCountsWithinChange": {str(gap): pair_count(records, target, gap) for gap in sorted({0, 1000, 10000, max_change})},
        "conditionalOnSingleOutputModel": conditional,
    }
    singles = [{**row, "possibleChangeZat": row["valueZat"] - target,
                "conditionalOnSingleOutputModel": conditional}
               for row in records if row["valueZat"] >= target]
    write_rows(output / "all-singles.jsonl", sorted(singles, key=lambda row: (row["possibleChangeZat"], row["id"])))
    all_pairs = []
    clustered = []
    for left, right in pair_indices(records, target, max_change):
        row = pair_record(left, right, target, conditional)
        all_pairs.append(row)
        if row["sameDecodedReceiver"] or any(row["shared"][x] for x in ("senders", "refunds", "fullUnifiedAddresses")):
            clustered.append(row)
    write_rows(output / "all-pairs-in-window.jsonl", all_pairs)
    write_rows(output / "clustered-pairs-in-window.jsonl", clustered)
    by_amount = lambda row: (row["possibleChangeZat"], row.get("hoursBeforeExit") if row.get("hoursBeforeExit") is not None else float("inf"), row["leftId"], row["rightId"])
    by_time = lambda row: (row.get("hoursBeforeExit") if row.get("hoursBeforeExit") is not None else float("inf"), row["possibleChangeZat"], row["leftId"], row["rightId"])
    dump(output / "shortlist-by-amount.json", sorted(clustered, key=by_amount)[:100])
    dump(output / "shortlist-by-time.json", sorted(clustered, key=by_time)[:100])
    stats.update(pairsWritten=len(all_pairs), clusteredPairsWritten=len(clustered),
                 largerChangePairsNotWritten=stats["allAmountCompatiblePairs"] - len(all_pairs))
    dump(output / "statistics.json", stats)
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--routes", type=Path, default=Path("challenge7-complete-routes/all_routes.jsonl"))
    parser.add_argument("--summaries", type=Path, default=Path("challenge7-payout-universe-data/payout-summaries.jsonl"))
    parser.add_argument("--summary-cache", type=Path, default=Path("challenge7-payout-universe-data/cache/cipherscan-txns"))
    parser.add_argument("--migrations", type=Path, default=Path("challenge7-migration-data/migrations.jsonl"))
    parser.add_argument("--decoded", type=Path, action="append", default=[])
    parser.add_argument("--exit-analysis", type=Path, action="append", default=[], help="Supplemental completed, hash-checked account-exit analysis.")
    parser.add_argument("--pending-enrichment", type=Path, action="append", default=[], help="Complete enriched eligible ledger; originals are replayed offline.")
    parser.add_argument("--pending-raw-dir", type=Path, default=Path("challenge7-pending-raw-data"))
    parser.add_argument("--output-dir", type=Path, default=Path("challenge7-baseline-v2-data"))
    parser.add_argument("--pair-max-change-zat", type=int, default=100_000)
    args = parser.parse_args()
    if args.pair_max_change_zat < 0:
        parser.error("--pair-max-change-zat must be nonnegative")
    output = args.output_dir
    live_dirs = {Path(x).resolve() for x in ("challenge7-complete-routes", "challenge7-payout-universe-data", "challenge7-note-budget-data", "challenge7-migration-data")}
    if any(output.resolve() == root or root in output.resolve().parents for root in live_dirs):
        parser.error("write to a separate analysis directory, not an existing collector directory")
    manifest = {}
    routes = load(args.routes, manifest)
    summaries = load(args.summaries, manifest)
    migration_rows = load(args.migrations, manifest)
    counts = Counter(routes=len(routes), summaries=len(summaries))
    links = defaultdict(list)
    unresolved = []
    omitted_later_hashes = set()
    internal_rows = []
    for route in routes:
        txids = payout_txids(route)
        if route_class(route) == "internal-intents":
            counts["internalIntentsRoutesExcludedFromNoteUniverse"] += 1
            internal_rows.append(route_link(route))
            continue
        if not txids:
            counts["destinationRoutesWithoutValidZcashHash"] += 1
            unresolved.append({**route_link(route), "reason": "no-valid-zcash-destination-hash", "destinationIdentifiers": route.get("destinationChainTxHashes") or []})
            continue
        hashes = route.get("destinationChainTxHashes") or []
        first = zcash_txid(hashes[0]) if hashes else None
        omitted_later_hashes.update(txid for txid in txids if txid != first)
        for txid in txids:
            links[txid].append(route_link(route))
    by_txid = {zcash_txid(row.get("zcashPayoutTxid")): row for row in summaries if zcash_txid(row.get("zcashPayoutTxid"))}
    counts["validZcashTxidsInRoutes"] = len(links)
    counts["validHashesMissedByFirstHashRule"] = len(omitted_later_hashes)
    missing = sorted(set(links) - set(by_txid))
    balances = []
    cache_manifest = hashlib.sha256()
    canonical_by_txid = {}
    for txid, summary in by_txid.items():
        if (integer(summary.get("actualIronwoodValueCreatedZat")) or 0) <= 0:
            continue
        detail = cache_detail(args.summary_cache, txid)
        cache_manifest.update(json.dumps(detail, sort_keys=True).encode())
        canonical_by_txid[txid] = detail.get("isCanonical")
        row = balance_record(summary, links.get(txid, []), detail)
        if row:
            balances.append(row)
    compatible = [row for row in balances if row["anchorEligibility"] == "height-compatible"]
    counts.update({"publicIronwoodBalances": len(balances), "heightCompatibleCanonicalBalances": len(compatible)})
    counts.update({"balanceEligibility_" + key: value for key, value in Counter(row["anchorEligibility"] for row in balances).items()})
    decoded = {}
    decode_errors = []
    packet_groups = [load(path, manifest) for path in args.decoded]
    pending_audits=[]
    for path in getattr(args,"pending_enrichment",[]):
        packets,audit=verified_pending_packets(path,args.pending_raw_dir,manifest)
        packet_groups.append(packets);pending_audits.append({"source":str(path.resolve()),**audit})
    connector_provenance = {}
    for path in getattr(args, "exit_analysis", []):
        packets, provenance = exit_note_packets(path, manifest)
        packet_groups.append(packets)
        connector_provenance.update(provenance)
    for packets in packet_groups:
        for packet in packets:
            txid = zcash_txid(packet.get("txid"))
            if not packet.get("ok") or not txid:
                decode_errors.append(packet)
                continue
            summary = by_txid.get(txid, {})
            height,time,canonical=packet_metadata(packet,summary,canonical_by_txid,txid)
            for note in packet.get("outputs", []):
                if note.get("pool") != "ironwood" or not note.get("recovered") or (integer(note.get("valueZat")) or 0) <= 0:
                    continue
                index = integer(note.get("actionIndex"))
                commitment = str(note.get("cmx") or "")
                if index is None or not re.fullmatch(r"[0-9a-fA-F]{64}", commitment) or not note.get("receiverRaw"):
                    decode_errors.append({"txid": txid, "error": "recovered output missing identity/receiver"})
                    continue
                matched_addresses = set(note.get("matchingUnifiedAddresses") or [])
                matched_links = [link for link in links.get(txid, []) if link.get("recipient") in matched_addresses]
                row = {
                    "id": f"{txid}:ironwood:{index}:{commitment}", "txid": txid,
                    "pool": "ironwood", "actionIndex": index, "cmx": commitment,
                    "valueZat": int(note["valueZat"]), "valueConfidence": "zero-ovk-decoded-output",
                    "receiverBytes": [note["receiverRaw"]], "memoHex": note.get("memoHex"),
                    "blockHeight": height, "blockTime": time,
                    "anchorEligibility": eligibility(height, canonical, time),
                    "routeRecipientMatched": bool(matched_links),
                    "destinationRole": "requested-route-recipient" if matched_links else "unattributed-recovered-output-may-be-change",
                    "routes": matched_links, **metadata(matched_links),
                }
                if packet.get("canonicalMetadataSource"):
                    row["canonicalMetadataSource"]=packet["canonicalMetadataSource"]
                    row["canonicalBlockHash"]=packet["canonicalBlockHash"]
                if packet.get("pendingRequestProvenance"):
                    proof=packet["pendingRequestProvenance"]
                    if proof.get("txid")!=txid or proof.get("evidenceClass")!="successful-descendant-pending-ID-not-settlement-by-itself":
                        raise ValueError("pending connector provenance identity/evidence class mismatch")
                    row["pendingConnectorProvenance"]=proof
                    receiver=str(proof.get("requestedReceiver") or "").removeprefix("zcash:")
                    row["pendingConnectorReceiverMatched"]=bool(receiver and receiver in matched_addresses)
                    if not matched_links and row["pendingConnectorReceiverMatched"]:
                        row["destinationRole"]="pending-connector-request-recipient-not-complete-execution-proof"
                if txid in connector_provenance:
                    proof = connector_provenance[txid]
                    receiver = proof["requestedReceiver"].removeprefix("zcash:")
                    row["connectorProvenance"] = proof
                    row["executedConnectorReceiverMatched"] = receiver in matched_addresses
                    if not matched_links and row["executedConnectorReceiverMatched"]:
                        row["destinationRole"] = "executed-connector-request-recipient"
                if row["id"] in decoded and decoded[row["id"]] != row:
                    raise ValueError("conflicting decoded output " + row["id"])
                decoded[row["id"]] = row
    eligible_notes = [row for row in decoded.values() if row["anchorEligibility"] == "height-compatible"]
    counts["decodedPositiveIronwoodOutputs"] = len(decoded)
    counts["heightCompatibleCanonicalDecodedNotes"] = len(eligible_notes)
    write_rows(output / "public-balances.jsonl", balances)
    write_rows(output / "decoded-notes.jsonl", decoded.values())
    write_rows(output / "decode-errors.jsonl", decode_errors)
    write_rows(output / "internal-intents-upstream-only.jsonl", internal_rows)
    write_rows(output / "unresolved-destination-routes.jsonl", unresolved)
    dump(output / "missing-payout-txids.json", missing)
    decode_queue = []
    for txid, summary in by_txid.items():
        iw = integer(summary.get("actualIronwoodValueCreatedZat")) or 0
        orch = integer(summary.get("actualOrchardValueCreatedZat")) or 0
        if iw > 0 or orch > 0:
            decode_queue.append({"txid": txid, "blockHeight": integer(summary.get("zcashBlockHeight")),
                                 "blockTime": summary.get("blockTime"), "ironwoodNetInflowZat": iw,
                                 "orchardNetInflowZat": orch, "routes": links.get(txid, [])})
    write_rows(output / "decode-queue.jsonl", decode_queue)
    queue_map = {row["txid"]: row for row in decode_queue}
    # A small diagnostic queue spans close singles, recent singles and every
    # structured pair in the configured interval; its truncation is explicit.
    priority_ids = {}
    eligible_singles = [row for row in compatible if row["valueZat"] >= TARGET]
    for row in sorted(eligible_singles, key=lambda row: (row["valueZat"], row["id"]))[:20]:
        priority_ids.setdefault(row["txid"], set()).add("closest-public-balance-single")
    oldest_time = datetime.min.replace(tzinfo=timezone.utc)
    for row in sorted(eligible_singles, key=lambda row: utc(row["blockTime"]) or oldest_time, reverse=True)[:20]:
        priority_ids.setdefault(row["txid"], set()).add("recent-public-balance-single")
    for left, right in pair_indices(compatible, TARGET, args.pair_max_change_zat):
        pair = pair_record(left, right, TARGET, True)
        if pair["sameDecodedReceiver"] or any(pair["shared"][x] for x in ("senders", "refunds", "fullUnifiedAddresses")):
            for row in (left, right):
                priority_ids.setdefault(row["txid"], set()).add("structured-public-balance-pair")
    priority_queue = [{**queue_map[txid], "priorityReasons": sorted(reasons)}
                      for txid, reasons in priority_ids.items() if txid in queue_map]
    priority_queue.sort(key=lambda row: utc(row["blockTime"]) or oldest_time, reverse=True)
    write_rows(output / "priority-decode-queue.jsonl", priority_queue)
    # Keep every smaller crossing; net balances are not individual note values.
    migration_budgets = []
    other_mixed = []
    for row in migration_rows:
        height = integer(row.get("height"))
        if height is not None and ACTIVATION <= height <= ANCHOR:
            if (integer(row.get("orchardValueLeavingZat")) or 0) <= 0 or (integer(row.get("ironwoodValueEnteringZat")) or 0) <= 0:
                other_mixed.append(row)
                continue
            migration_budgets.append({**row, "evidenceClass": "migration-net-balance-NOT-a-note",
                                     "netInflowAtLeastTarget": (integer(row.get("ironwoodValueEnteringZat")) or 0) >= TARGET})
    write_rows(output / "all-migration-budgets.jsonl", migration_budgets)
    write_rows(output / "other-mixed-pool-transactions.jsonl", other_mixed)
    counts["migrationBudgetsRetained"] = len(migration_budgets)
    counts["subTargetMigrationBudgetsRetained"] = sum(not row["netInflowAtLeastTarget"] for row in migration_budgets)
    print("offline inventories ready; searching all pairs in configured intervals", flush=True)
    model_stats = search(compatible, output / "conditional-balance-search", TARGET, args.pair_max_change_zat, True)
    note_stats = search(eligible_notes, output / "decoded-note-search", TARGET, args.pair_max_change_zat, False)
    manifest.update({"scriptSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     "readIronwoodSummaryCacheDigest": cache_manifest.hexdigest(),
                     "createdAt": datetime.now(timezone.utc).isoformat(),
                     "pendingEnrichmentAudits":pending_audits,
                     "parameters": {"targetZat": TARGET, "activationHeight": ACTIVATION, "anchorHeight": ANCHOR,
                                    "pairMaxChangeZat": args.pair_max_change_zat},
                     "counts": dict(counts), "conditionalBalanceSearch": model_stats, "decodedNoteSearch": note_stats})
    dump(output / "manifest.json", manifest)
    report = ["# Challenge 7 corrected offline baseline", "", "Status: unresolved. No address is confirmed.", "",
              "## Inventory", "", *[f"- {key}: {value:,}" for key, value in sorted(counts.items())], "",
              f"- Missing valid payout summaries: {len(missing):,}", "",
              "## Conditional pool-balance search", "",
              "These are transaction aggregates, NOT verified individual note values. Every listed",
              "combination assumes each aggregate represents exactly one available input note.", "",
              f"- All amount-compatible pairs: {model_stats['allAmountCompatiblePairs']:,}",
              f"- All pairs retained within {args.pair_max_change_zat:,} zats of change: {model_stats['pairsWritten']:,}",
              f"- Structurally shared-metadata pairs in that interval: {model_stats['clusteredPairsWritten']:,}", "",
              "Large-change pairs remain possible and are counted but not materialized in this run.",
              "All amount-compatible singles are retained without an upper value filter.", "",
              "## Decoded-note search", "",
              f"- Eligible, recovered positive notes: {len(eligible_notes):,}",
              f"- Pairs in configured interval: {note_stats['pairsWritten']:,}", "",
              "Decoded outputs establish their own value/receiver/commitment, not whether the target",
              "spent them. Height compatibility relies on cached explorer canonicality/height and",
              "the previously reconstructed anchor; independent chain verification remains desirable.", "",
              "No explorer estimate enters either search. Missing data is kept in queues.",
              "Internal Intents movements are retained only as upstream records.",
              "All route links are preserved; repeated/service identities are not ownership proof.",
              "Full-UA matches are not labelled decoded-receiver matches.", "",
              "## Next inputs", "",
              "Use the public raw-batch collector for the declared payout inventory, then rerun with --decoded.",
              "Use the independent NEAR execution ledger to audit unmatched legacy requests; no Dune payment is needed.",
              "This command is offline. Inventory completion does not resolve opaque notes, private consolidation or the target nullifiers.", ""]
    atomic_write(output / "report.md", "\n".join(report))
    print(f"done: {output / 'report.md'}", flush=True)


if __name__ == "__main__":
    main()
