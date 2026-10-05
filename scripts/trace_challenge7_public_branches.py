#!/usr/bin/env python3
"""Bounded follow-up of case B's public UTXOs and case D's older shielding.

Cache-only by default. --fetch permits capped, paced public reads, never a
wallet signature or transaction submission. Collector databases remain read-only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from investigate_challenge7_account_links import Evidence, ZEC_API, SUCCESS, load_trace, builder_packets, pending_payouts, compare_raw_packet
from trace_challenge7_free_near import CheckpointStop, digest, fetch_batch, normalize, withdrawal_records

ANCHOR = 3488703
BRIDGE_ADDRESS = "t1Ku2KLyndDPsR32jwnrTMd3yvi9tfFP8ML"
FORWARD_TX = "c6308d0b39391c42179dc323f10981c6066672730f4d060c7ec7fd2ef5af7d49"
EXTRA_TX = "84c09ed63563bc96e5ce6ab6132dde3a6f99ec595aa36acba92601bfb007f7a7"
OLDER_SHIELDS = [
    "0a02c95ca78a0d07176f50ee98551f3f51725fbe9f9be2316263b683711b0cab",
    "fb6c0fbb7d20f63aba10a98f995471172145fbc73ee9fde7b706ce4cfa2ad128",
    "1a1f26c8859e448560afaefff70c7b1776dbcead1d56a97513bc2674dbe9f951",
]


def spends_outpoint(detail, txid, vout):
    return any(x.get("prev_txid") == txid and int(x["prev_vout"]) == vout
               for x in detail.get("inputs") or [])


def bundle_budget(decoded):
    """Conditional value-conservation bounds, not note recovery or proof verification."""
    budgets = []
    if not decoded.get("ok"):
        return budgets
    for b in decoded.get("bundles") or []:
        no_positive_input = b.get("anchorIsEmptyTree") is True or b.get("spendsEnabled") is False
        net = -int(b["valueBalanceZat"])
        budgets.append({"pool": b["pool"], "netInflowZat": net,
                        "positivePrivateInputValueExcluded": no_positive_input,
                        "reason": "empty-tree-anchor" if b.get("anchorIsEmptyTree") is True else "spends-disabled" if b.get("spendsEnabled") is False else "nonempty-anchor-and-spends-enabled",
                        "totalOutputValueZat": net if no_positive_input and net >= 0 else None,
                        "maximumIndividualOutputValueZat": net if no_positive_input and net >= 0 else None,
                        "outputValuesRecovered": False,
                        "historicalCircuitWarning": "InsecureV1" in b.get("bundleVersion", ""),
                        "assumptions": "Correct mined raw bytes, accepted sound proof/value balance and collision-resistant commitment tree. Decoder does not verify proof or independent block inclusion; V6 txid alone does not bind anchor."})
    return budgets


def trusted_deposits(trace, txids):
    result = []
    for call in trace["calls"]:
        args = call.get("args") or {}
        memo = args.get("memo") or {}
        if (call["source"] != "receipt" or call["predecessor"] != "bridge-mng.near"
                or call["receiver"] != "omft.near" or call["method"] != "ft_deposit"
                or call["executionStatus"] not in SUCCESS or not isinstance(memo, dict)
                or memo.get("networkType") != "zec" or memo.get("chainId") != "mainnet"
                or memo.get("txHash") not in txids or args.get("token") != "zec"
                or args.get("owner_id") != "intents.near"):
            continue
        msg = args.get("msg") or {}
        account = msg.get("receiver_id") if isinstance(msg, dict) else None
        statuses = {o["receiptId"]: o["executionStatus"] for o in trace["outcomes"]}
        mints = []
        for log in trace["logs"]:
            event = log.get("decoded")
            if (log["receiver"] != "intents.near" or statuses.get(log["receiptId"]) not in SUCCESS
                    or not isinstance(event, dict) or event.get("standard") != "nep245"
                    or event.get("event") != "mt_mint"):
                continue
            for item in event.get("data") or []:
                if item.get("owner_id") == account:
                    tokens, amounts = item.get("token_ids") or [], item.get("amounts") or []
                    if len(tokens) != len(amounts):
                        raise ValueError("NEP245 mint array lengths disagree")
                    for token, amount in zip(tokens, amounts):
                        if token == "nep141:zec.omft.near":
                            mints.append({"receiptId": log["receiptId"], "logIndex": log["index"], "amountZat": str(int(amount))})
        result.append({"nearRoot": trace["nearTransactionHash"], "receiptId": call["receiptId"],
                       "blockTime": call["blockTime"], "zecDepositTxid": memo["txHash"],
                       "amountZat": args["amount"], "intentsAccount": account, "mintEvents": mints,
                       "mintAmountMatches": any(m["amountZat"] == args["amount"] for m in mints),
                       "warning": "Explicit bridge deposit identifier and executed credit, not proof of Litecoin settlement or real-world ownership."})
    return result


def internal_swap_funding(trace, sender, recipient, token, amount):
    statuses = {o["receiptId"]: o["executionStatus"] for o in trace["outcomes"]}
    matches = []
    for log in trace["logs"]:
        event = log.get("decoded")
        if (log["receiver"] != "intents.near" or statuses.get(log["receiptId"]) not in SUCCESS
                or not isinstance(event, dict) or event.get("standard") != "nep245"
                or event.get("event") != "mt_transfer"):
            continue
        for item in event.get("data") or []:
            if item.get("old_owner_id") != sender or item.get("new_owner_id") != recipient:
                continue
            tokens, amounts = item.get("token_ids") or [], item.get("amounts") or []
            if len(tokens) != len(amounts):
                raise ValueError("NEP245 array lengths disagree")
            for t, a in zip(tokens, amounts):
                if t == token and str(int(a)) == str(int(amount)):
                    matches.append({"root": trace["nearTransactionHash"], "receiptId": log["receiptId"],
                                    "logIndex": log["index"], "senderAccount": sender,
                                    "recipientAccount": recipient, "token": token, "amountRaw": str(int(a))})
    return matches


class Reader(Evidence):
    def __init__(self, args, known):
        super().__init__(args.output_dir, args.fetch, args.max_http_calls, args.delay)
        self.args, self.known = args, known
        self.reused = {}

    def request(self, url, body=None):
        data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        key = hashlib.sha256(url.encode() + b"\n" + (data or b"")).hexdigest()
        old = self.args.case_dir / "http-responses" / (key + ".json")
        if old.exists() and not (self.output / "http-responses" / (key + ".json")).exists():
            value = json.loads(old.read_text())
            if value["url"] != url or value.get("request") != body:
                raise ValueError("cached request identity mismatch")
            if hashlib.sha256(value["rawUtf8"].encode()).hexdigest() != value["responseBytesSha256"]:
                raise ValueError("cached original response hash mismatch")
            self.reused[str(old.resolve())] = digest(old)
            return value["response"]
        return super().request(url, body)

    def tx(self, txid):
        result = self.known.get(txid) or self.request(f"{ZEC_API}/tx/{txid}")
        if result is None:
            raise CheckpointStop(f"missing cached transaction {txid}; --fetch required")
        if result.get("txid") != txid:
            raise ValueError("transaction identity mismatch")
        if result.get("isCanonical") is not True or int(result["blockHeight"]) > ANCHOR:
            raise ValueError("transaction is not verified by the indexer as canonical and before the target anchor")
        return result

    def decode(self, txid, detail):
        raw = self.request(f"{ZEC_API}/tx/{txid}/raw")
        if raw is None:
            raise CheckpointStop(f"missing cached raw {txid}; --fetch required")
        packet = {"hex": raw["hex"], "expectedTxid": txid, "blockHeight": int(detail["blockHeight"]),
                  "blockTime": detail["blockTime"], "isCanonical": detail.get("isCanonical")}
        result = json.loads(subprocess.run([str(self.args.decoder.resolve())], input=json.dumps(packet)+"\n",
                           text=True, capture_output=True, check=True, timeout=30).stdout)
        if not result.get("ok"):
            raise ValueError("raw decoding failed: " + str(result.get("error")))
        return result


def investigate(args):
    if args.output_dir.resolve() in (args.case_dir.resolve(), args.ledger_dir.resolve()):
        raise ValueError("analysis output must be separate from its inputs")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cases = [json.loads(s) for s in (args.case_dir / "cases.jsonl").read_text().splitlines() if s]
    by_case = {c["caseNumber"]: c for c in cases}
    known = {h: d for c in cases for h, d in c.get("transactionDetails", {}).items()}
    known.update({x["detail"]["txid"]: x["detail"] for c in cases for x in c.get("publicSecondHopSpends", [])})
    reader = Reader(args, known)
    result = {"challengeSolved": False, "publicOutpoints": [], "extraInputAncestry": [],
              "olderShielding": [], "internalSwapFunding": [], "bridgeDeposits": []}
    dbpath = args.ledger_dir / "ledger.sqlite3"
    db = sqlite3.connect(f"file:{dbpath.resolve()}?mode=ro", uri=True)
    reused_near, traces, stopped = {}, {}, None
    try:
        # Only the two declared outputs of the observed branch, no hot-wallet BFS.
        forward = reader.tx(FORWARD_TX)
        for vout in (0, 1):
            output = next(o for o in forward["outputs"] if int(o["vout_index"]) == vout)
            item = {"sourceOutpoint": f"{FORWARD_TX}:{vout}", "output": output, "spends": [],
                    "warning": "Public ancestry, not value allocation between mixed inputs or common ownership."}
            result["publicOutpoints"].append(item)
            if output.get("spent") is False:
                item["status"] = "indexed-unspent-in-preserved-post-target-evidence"
                continue
            pages, snapshots = [], set()
            for page_no in range(1, args.max_address_pages + 1):
                page = reader.request(f"{ZEC_API}/address/{output['address']}?page={page_no}&limit=100")
                if page is None:
                    raise CheckpointStop("missing address snapshot; --fetch required")
                if page.get("address") != output["address"]:
                    raise ValueError("address identity mismatch")
                pages.append(page)
                pagination = page.get("pagination") or {}
                snapshots.add(pagination.get("snapshotHeight"))
                for summary in page.get("transactions") or []:
                    if int(summary.get("inputValue") or 0) <= 0 or not int(forward["blockHeight"]) <= int(summary["blockHeight"]) <= ANCHOR:
                        continue
                    detail = reader.tx(summary["txid"])
                    if spends_outpoint(detail, FORWARD_TX, vout):
                        item["spends"].append(detail)
                if pagination.get("hasNext") is False:
                    break
            item["addressPages"] = pages
            item["historyCompleteAtSingleSnapshot"] = len(snapshots) == 1 and None not in snapshots and pages[-1].get("pagination", {}).get("hasNext") is False
            if len(item["spends"]) > 1:
                raise ValueError("multiple canonical spend candidates: explicit conflict, not nearest-time choice")
            item["status"] = "indexed-exact-outpoint-spend" if item["spends"] else "unresolved-spend-history-bounded"
            item["reachesLegacyBridge"] = any(o.get("address") == BRIDGE_ADDRESS for d in item["spends"] for o in d.get("outputs") or [])
            print(f"public outpoint={item['sourceOutpoint']} status={item['status']}", flush=True)

        extra = reader.tx(EXTRA_TX)
        if not spends_outpoint(forward, EXTRA_TX, 1):
            raise ValueError("extra input does not feed the observed forward transaction")
        result["extraInputParent"] = extra
        # One upstream level, preserving every input. Do not choose a funder by amount.
        for source in extra["inputs"]:
            parent = reader.tx(source["prev_txid"])
            output = next(o for o in parent["outputs"] if int(o["vout_index"]) == int(source["prev_vout"]))
            if int(output["value"]) != int(source["value"]) or output.get("address") != source.get("address"):
                raise ValueError("upstream prevout disagrees with consumer metadata")
            result["extraInputAncestry"].append({"sourceOutpoint": f"{source['prev_txid']}:{source['prev_vout']}", "parent": parent})

        for txid in OLDER_SHIELDS:
            detail = reader.tx(txid)
            decoded = reader.decode(txid, detail)
            parent_links = []
            raw_prevouts = {(i["prevTxid"], i["prevVout"]) for i in decoded["transparentInputs"]}
            api_prevouts = {(i["prev_txid"], int(i["prev_vout"])) for i in detail["inputs"]}
            if raw_prevouts != api_prevouts:
                raise ValueError("raw shielding inputs disagree with API metadata")
            for i in detail["inputs"]:
                parent = reader.tx(i["prev_txid"])
                output = next(o for o in parent["outputs"] if int(o["vout_index"]) == int(i["prev_vout"]))
                if int(output["value"]) != int(i["value"]) or output.get("address") != i.get("address"):
                    raise ValueError("shielding prevout disagrees with parent output")
                parent_links.append({"sourceOutpoint": f"{i['prev_txid']}:{i['prev_vout']}", "parent": parent})
            result["olderShielding"].append({"detail": detail, "decoded": decoded,
                                            "parentLinks": parent_links, "budgets": bundle_budget(decoded)})
            print(f"older shield={txid} recovered={sum(o['recovered'] for o in decoded['outputs'])}", flush=True)
        # Revisit C's opaque payout with the new anchor diagnostic, without
        # changing the original case files or silently assigning a receiver.
        for candidate in by_case[3].get("probeBudgetCandidates", []):
            detail = next(d for d in by_case[3]["earlyCompactProbe"]["transactions"] if d["txid"] == candidate["txid"])
            decoded = reader.decode(candidate["txid"], detail)
            result["legacyProbeRecheck"] = {"txid": candidate["txid"], "decoded": decoded, "budgets": bundle_budget(decoded),
                                           "receiverAssociation": "unverified-time-and-offset-correlation"}

        shared = by_case[4]["signedWithdrawalAccounts"][0]["intentsAccountId"]
        funding = {json.loads(s)["nearTransactionHash"]: json.loads(s) for s in (args.case_dir / "funding-traces.jsonl").read_text().splitlines() if s}
        for route in by_case[4]["internalIntentsAccountRoutes"]:
            matches = [m for h in route.get("nearTxHashes") or [] if h in funding
                       for m in internal_swap_funding(funding[h], shared, route["depositAddress"], route["originAsset"], route["amountIn"])]
            result["internalSwapFunding"].append({"quoteCreatedAt": route["createdAt"], "originAsset": route["originAsset"],
                                                 "amountIn": route["amountIn"], "amountOutZat": route["amountOut"], "events": matches,
                                                 "warning": "Earlier internal balance funds this swap; token contract is not an external EVM sender."})
        # A declared three-hour cached receipt search around the deposit.
        # Search both the user deposit transaction and its bridge sweep, because
        # the BRIDGED_FROM memo may identify the former, not the hot-wallet sweep.
        rows = db.execute("SELECT r.hash,r.data FROM roots r JOIN method_counts m ON r.hash=m.root WHERE m.receiver='zec.omft.near' AND m.method='ft_deposit' AND json_extract(r.data,'$.blockTime') >= '2026-07-29T18:30:00' AND json_extract(r.data,'$.blockTime') < '2026-07-29T21:30:00'").fetchall()
        result["bridgeDepositSearch"] = {"from": "2026-07-29T18:30:00Z", "toExclusive": "2026-07-29T21:30:00Z", "rootsInspected": len(rows), "method": "cached zec.omft.near ft_deposit trees"}
        for root, data in rows:
            metadata = json.loads(data)
            source = Path(metadata["sourceResponse"])
            reused_near[str(source.resolve())] = digest(source)
            trace = load_trace(db, root, {})
            if trace is None or not trace["treeReferencesComplete"]:
                raise ValueError("missing/incomplete cached deposit tree")
            found = trusted_deposits(trace, {FORWARD_TX, *(d["txid"] for i in result["publicOutpoints"] for d in i["spends"])})
            if found:
                result["bridgeDeposits"].extend(found)
                traces[root] = trace
        # Associations are explorer metadata only. A zero match is not proof
        # that the actual legacy NEAR withdrawal does not exist.
        wanted = {d["txid"] for x in result["extraInputAncestry"] for d in [x["parent"]]}
        wanted.update(x["parent"]["txid"] for s in result["olderShielding"] for x in s["parentLinks"])
        result["recordedRouteAssociations"] = []
        for row in db.execute("SELECT data FROM routes"):
            route = json.loads(row[0])
            matches = sorted(wanted.intersection(route.get("destinationChainTxHashes") or []))
            if matches:
                result["recordedRouteAssociations"].append({"payoutTxids": matches, "route": route, "evidenceClass": "explorer-route-association-not-executed-withdrawal-proof"})
        # The older transparent payouts can use nzec.bridge.near, outside the
        # completed zec.omft.near inventory. Reconcile the existing connector
        # listing by actual input outpoints, then verify its full execution tree.
        older_parents = {x["parent"]["txid"]: x["parent"] for s in result["olderShielding"] for x in s["parentLinks"]}
        requests = []
        for line in args.raw_requests.open():
            request = json.loads(line)
            packet_inputs = set(request.get("connectorInputs") or [])
            if not packet_inputs:
                continue
            for txid, parent in older_parents.items():
                parent_inputs = {f"{i['prev_txid']}:{i['prev_vout']}" for i in parent["inputs"]}
                if packet_inputs == parent_inputs:
                    requests.append({"payoutTxid": txid, "request": request})
        older_roots = {x["request"]["nearTransactionHash"] for x in requests}
        older_roots.update(h for a in result["recordedRouteAssociations"] if set(a["payoutTxids"]).intersection(older_parents) for h in a["route"].get("nearTxHashes") or [])
        own = {}
        for path in sorted((args.output_dir / "responses").glob("*.json")):
            for entry in json.loads(path.read_text()).get("transactions") or []:
                own[entry["transaction"]["hash"]] = normalize(entry)
        old_traces = {h: t for h in older_roots if (t := load_trace(db, h, own)) is not None}
        missing = sorted(older_roots - old_traces.keys())
        if missing:
            if not args.fetch:
                raise CheckpointStop("missing older payout NEAR trees; --fetch required")
            for offset in range(0, len(missing), 20):
                if reader.calls >= reader.limit:
                    raise CheckpointStop("per-run HTTP limit reached before NEAR batch")
                payload, path, online = fetch_batch(missing[offset:offset+20], args.output_dir, args.delay, 30, 1)
                reader.calls += int(online)
                for entry in payload["transactions"]:
                    h = entry["transaction"]["hash"]
                    if h not in missing[offset:offset+20]:
                        raise ValueError("unrequested older NEAR root returned")
                    old_traces[h] = normalize(entry)
        if older_roots - old_traces.keys() or any(not t["treeReferencesComplete"] for t in old_traces.values()):
            raise ValueError("missing/incomplete older payout execution tree")
        result["olderNearWithdrawals"] = []
        for h, trace in old_traces.items():
            result["olderNearWithdrawals"].extend(withdrawal_records(trace, {"payoutTxids": [], "routes": []}))
            traces[h] = trace
        result["olderLegacyFundingTransfers"] = []
        for withdrawal in result["olderNearWithdrawals"]:
            for account in withdrawal["signedWithdrawalAccounts"]:
                incoming = internal_swap_funding(old_traces[withdrawal["nearTransactionHash"]], shared,
                                                 account["intentsAccountId"], "nep141:zec.omft.near", withdrawal["requestedAmountZat"])
                if incoming:
                    day = withdrawal["blockTime"][:10]
                    day_credits = [c for c in by_case[4]["verifiedIncomingZecEvents"] if (c.get("blockTime") or "")[:10] == day]
                    result["olderLegacyFundingTransfers"].append({"withdrawalRoot": withdrawal["nearTransactionHash"],
                                                                 "transferEvents": incoming, "recordedSameDayCreditEvents": day_credits,
                                                                 "sameDayCreditSumZat": str(sum(int(c["amountZat"]) for c in day_credits)),
                                                                 "warning": "Executed account transfer; credit sum fit is not a complete account-balance or exclusive funding proof."})
        result["olderConnectorPayoutLinks"] = []
        for selected in requests:
            request, txid = selected["request"], selected["payoutTxid"]
            trace = old_traces[request["nearTransactionHash"]]
            packets = [p for p in builder_packets(trace) if p["receiptId"] == request["receiptId"]]
            pending = pending_payouts(trace)
            decoded = reader.decode(txid, older_parents[txid])
            if len(packets) != 1:
                raise ValueError("older executed builder packet missing or ambiguous")
            result["olderConnectorPayoutLinks"].append({"payoutTxid": txid, "nearRoot": trace["nearTransactionHash"],
                                                       "selectedRequest": request, "actualBuilderPacket": packets[0],
                                                       "pendingPayoutIds": pending,
                                                       "explicitPendingIdMatches": any(p["txid"] == txid for p in pending),
                                                       "rawComparison": compare_raw_packet(packets[0], decoded), "rawDecode": decoded,
                                                       "executedOriginTransferCallbacks": [c for c in trace["calls"] if c["source"] == "receipt" and c["receiver"] == "omni.bridge.near" and c["method"] == "submit_transfer_to_btc_connector_callback" and c["executionStatus"] in SUCCESS],
                                                       "warning": "Execution-to-public-payout link, not shielded note attribution or complete upstream funding."})
    except (CheckpointStop, OSError, ValueError, StopIteration, subprocess.SubprocessError) as exc:
        stopped = str(exc)
        print("checkpoint stop: " + stopped, flush=True)
    finally:
        db.close()
        dump(args.output_dir / "analysis.json", result)
        write_rows(args.output_dir / "bridge-deposit-traces.jsonl", [traces[k] for k in sorted(traces)])
        manifest = {"createdAt": datetime.now(timezone.utc).isoformat(), "challengeSolved": False,
                    "stopped": stopped, "newHttpCalls": reader.calls, "analysisSha256": digest(args.output_dir / "analysis.json"),
                    "casesInputSha256": digest(args.case_dir / "cases.jsonl"), "fundingInputSha256": digest(args.case_dir / "funding-traces.jsonl"),
                    "ledgerManifestSha256": digest(args.ledger_dir / "manifest.json"), "scriptSha256": digest(Path(__file__)),
                    "rawRequestsInputSha256": digest(args.raw_requests),
                    "decoderSha256": digest(args.decoder), "decoderSourceSha256": digest(Path("decoder/src/bin/note_ledger.rs")),
                    "decoderCargoLockSha256": digest(Path("decoder/Cargo.lock")), "reusedHttpResponses": reader.reused,
                    "reusedNearResponses": reused_near,
                    "savedNearResponses": [{"path": str(p.resolve()), "sha256": digest(p)} for p in sorted((args.output_dir / "responses").glob("*.json"))],
                    "savedHttpResponses": [{"path": str(p.resolve()), "sha256": digest(p)} for p in sorted((args.output_dir / "http-responses").glob("*.json"))]}
        dump(args.output_dir / "manifest.json", manifest)
    print(f"done: {args.output_dir}/analysis.json; stopped={stopped}", flush=True)
    return 2 if stopped else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--case-dir", type=Path, default=Path("challenge7-account-link-data"))
    p.add_argument("--ledger-dir", type=Path, default=Path("challenge7-withdrawal-ledger-data"))
    p.add_argument("--output-dir", type=Path, default=Path("challenge7-public-branch-data"))
    p.add_argument("--decoder", type=Path, default=Path("decoder/target/release/note_ledger"))
    p.add_argument("--raw-requests", type=Path, default=Path("challenge7-payout-universe-data/raw-withdrawals.jsonl"))
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--max-http-calls", type=int, default=20)
    p.add_argument("--max-address-pages", type=int, default=2)
    p.add_argument("--delay", type=float, default=3)
    args = p.parse_args()
    if args.delay < 1 or args.max_http_calls < 0 or not 1 <= args.max_address_pages <= 5:
        p.error("delay >=1, nonnegative HTTP limit and address pages 1..5 required")
    return investigate(args)


if __name__ == "__main__":
    raise SystemExit(main())
