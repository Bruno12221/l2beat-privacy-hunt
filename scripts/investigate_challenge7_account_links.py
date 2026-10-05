#!/usr/bin/env python3
"""Bounded public-evidence investigation of the four account-linked withdrawals.

Offline by default. Separate outputs; never alters the completed withdrawal DB.
Explicit --fetch reads public NEAR trees, transparent Zcash address histories,
and the recorded Arbitrum deposit. No JWT, Dune, signing or nearest-time proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

from analyze_challenge7_baseline import dump, utc, write_rows, cache_detail
from collect_orchard_ironwood_migrations import normalize_hash
from trace_challenge7_free_near import CheckpointStop, digest, fetch_batch, normalize

ZEC_API = "https://api.mainnet.cipherscan.app/api"
ARB_RPC = "https://arb1.arbitrum.io/rpc"
ZEC_TOKEN = "nep141:zec.omft.near"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SUCCESS = ("SuccessValue", "SuccessReceiptId")


def timestamp_ns(value):
    # Python 3.9 fromisoformat cannot read nine fractional digits. Preserve
    # them explicitly rather than round through floating-point seconds.
    match = re.fullmatch(r"(.+?)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", value)
    if not match:
        raise ValueError(f"unsupported timestamp: {value}")
    base = utc(match[1] + match[3])
    seconds = (base - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(seconds=1)
    return seconds * 1_000_000_000 + int((match[2] or "0").ljust(9, "0"))


def route_before(route, withdrawal):
    return timestamp_ns(route["createdAt"]) <= timestamp_ns(withdrawal["blockTime"])


def account_credits(trace, account):
    result = []
    status_by_receipt = {r["receiptId"]: r["executionStatus"] for r in trace["outcomes"]}
    clocks = {c["receiptId"]: c for c in trace.get("calls", []) if c["source"] == "receipt"}
    for log in trace["logs"]:
        event = log.get("decoded")
        if log.get("receiver") != "intents.near" or not isinstance(event, dict):
            continue
        if event.get("standard") != "nep245" or status_by_receipt.get(log["receiptId"]) not in SUCCESS:
            continue
        kind = event.get("event")
        if kind not in ("mt_transfer", "mt_mint"):
            continue
        for item in event.get("data") or []:
            recipient = item.get("new_owner_id") if kind == "mt_transfer" else item.get("owner_id")
            if recipient != account or item.get("old_owner_id") == account:
                continue
            tokens, amounts = item.get("token_ids") or [], item.get("amounts") or []
            if len(tokens) != len(amounts):
                raise ValueError("NEP245 token/amount array length mismatch")
            for index, (token, amount) in enumerate(zip(tokens, amounts)):
                if token == ZEC_TOKEN:
                    clock = clocks.get(log["receiptId"], {})
                    result.append({"root": trace["nearTransactionHash"], "receiptId": log["receiptId"],
                                   "logIndex": log["index"], "tokenIndex": index,
                                   "kind": kind, "account": account, "amountZat": str(int(amount)),
                                   "sender": item.get("old_owner_id"), "executionStatus": status_by_receipt.get(log["receiptId"]),
                                   "blockTimestampNs": clock.get("blockTimestampNs"), "blockTime": clock.get("blockTime")})
    return result


def classify_credits(credits, withdrawal_time):
    cutoff = timestamp_ns(withdrawal_time)
    before, later, unknown = [], [], []
    for credit in credits:
        clock = credit.get("blockTimestampNs")
        if clock is None:
            unknown.append(credit)
        elif int(clock) <= cutoff:
            before.append(credit)
        else:
            later.append(credit)
    return before, later, unknown


def cross_chain_deposits(trace, txid, chain_id):
    found = []
    for call in trace.get("calls", []):
        if (call["source"] != "receipt" or call["receiver"] != "omft.near"
                or call["predecessor"] != "bridge-mng.near" or call["method"] != "ft_deposit"
                or call["executionStatus"] not in SUCCESS):
            continue
        args = call.get("args") or {}
        memo = args.get("memo") or {}
        if not isinstance(memo, dict) or memo.get("networkType") != "eth":
            continue
        if str(memo.get("chainId")) != str(chain_id) or str(memo.get("txHash", "")).lower() != txid.lower():
            continue
        found.append({"root": trace["nearTransactionHash"], "receiptId": call["receiptId"],
                      "memo": memo, "token": args.get("token"), "amountRaw": args.get("amount"),
                      "ownerId": args.get("owner_id"), "depositIntentsAccount": (args.get("msg") or {}).get("receiver_id"),
                      "executionStatus": call["executionStatus"], "blockTime": call.get("blockTime")})
    return found


def executed_intents_transfers(trace, account):
    statuses = {r["receiptId"]: r["executionStatus"] for r in trace["outcomes"]}
    found = []
    for log in trace["logs"]:
        event = log.get("decoded")
        if (log.get("receiver") != "intents.near" or statuses.get(log["receiptId"]) not in SUCCESS
                or not isinstance(event, dict) or event.get("standard") != "dip4" or event.get("event") != "transfer"):
            continue
        for item in event.get("data") or []:
            if item.get("receiver_id") == account and ZEC_TOKEN in (item.get("tokens") or {}):
                found.append({"root": trace["nearTransactionHash"], "receiptId": log["receiptId"],
                              "logIndex": log["index"], **item})
    return found


def evm_transfers(receipt, token, sender, recipient):
    matches = []
    for log in receipt.get("logs") or []:
        topics = log.get("topics") or []
        if len(topics) != 3 or topics[0].lower() != TRANSFER_TOPIC or log.get("removed") is True:
            continue
        if log.get("address", "").lower() != token.lower():
            continue
        source, dest = "0x" + topics[1][-40:], "0x" + topics[2][-40:]
        if source.lower() == sender.lower() and dest.lower() == recipient.lower():
            matches.append({"from": source, "to": dest, "token": log["address"],
                            "amountRaw": str(int(log["data"], 16)), "logIndex": int(log["logIndex"], 16)})
    return matches


def pending_payouts(trace):
    statuses = {r["receiptId"]: r["executionStatus"] for r in trace["outcomes"]}
    found = []
    for log in trace["logs"]:
        event = log.get("decoded")
        if log.get("receiver") != "zcash-connector.bridge.near" or statuses.get(log["receiptId"]) not in SUCCESS or not isinstance(event, dict):
            continue
        if event.get("standard") != "bridge" or event.get("event") != "generate_btc_pending_info":
            continue
        for item in event.get("data") or []:
            txid = item.get("btc_pending_id")
            if isinstance(txid, str) and re.fullmatch(r"[0-9a-fA-F]{64}", txid):
                found.append({"txid": txid.lower(), "builderRoot": trace["nearTransactionHash"],
                              "receiptId": log["receiptId"], "logIndex": log["index"],
                              "evidenceClass": "explicit-connector-pending-transaction-ID-not-yet-settlement"})
    return found


def builder_packets(trace):
    packets = []
    for call in trace["calls"]:
        if call["source"] != "receipt" or call["receiver"] != "zcash-connector.bridge.near" or call["method"] != "ft_on_transfer" or call["executionStatus"] not in SUCCESS:
            continue
        args = call.get("args") or {}
        msg = args.get("msg") or {}
        withdraw = msg.get("Withdraw") if isinstance(msg, dict) else None
        if isinstance(withdraw, dict):
            packets.append({"receiptId": call["receiptId"], "amountZat": args.get("amount"), **withdraw})
    return packets


def compare_raw_packet(packet, decoded):
    if not decoded.get("ok"):
        return {"verified": False, "reason": "raw decoder failed"}
    inputs = [f"{x['prevTxid']}:{x['prevVout']}" for x in decoded.get("transparentInputs") or []]
    outputs = [{"value": int(x["valueZat"]), "script_pubkey": x["scriptPubKeyHex"]} for x in decoded.get("transparentOutputs") or []]
    expected = [{"value": int(x["value"]), "script_pubkey": x["script_pubkey"].lower()} for x in packet.get("output") or []]
    return {"verified": inputs == packet.get("input") and outputs == expected and not decoded.get("bundles"),
            "inputsMatch": inputs == packet.get("input"), "outputsMatch": outputs == expected,
            "hasShieldedBundles": bool(decoded.get("bundles")), "computedTxid": decoded["txid"],
            "warning": "Raw payout serialization match, not a Challenge 7 private-spend link."}


class Evidence:
    def __init__(self, output, fetch, limit, delay):
        self.output, self.fetch, self.limit, self.delay = output, fetch, limit, delay
        self.calls = 0
        self.index = []

    def request(self, url, body=None):
        data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        key = hashlib.sha256(url.encode() + b"\n" + (data or b"")).hexdigest()
        path = self.output / "http-responses" / (key + ".json")
        if path.exists():
            envelope = json.loads(path.read_text())
        else:
            if not self.fetch:
                return None
            if self.calls >= self.limit:
                raise CheckpointStop("per-run HTTP limit reached")
            time.sleep(self.delay)
            self.calls += 1
            headers = {"accept": "application/json", "user-agent": "l2beat-public-evidence/1.0"}
            if body is not None:
                headers["content-type"] = "application/json"
            req = urllib.request.Request(url, data=data, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as response:
                    raw = response.read()
                    payload = json.loads(raw)
                    envelope = {"url": url, "request": body, "httpStatus": response.status,
                                "fetchedAt": datetime.now(timezone.utc).isoformat(),
                                "responseBytesSha256": hashlib.sha256(raw).hexdigest(),
                                "rawUtf8": raw.decode(), "response": payload}
                dump(path, envelope)
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403, 429):
                    raise CheckpointStop(f"HTTP {exc.code}; Retry-After={exc.headers.get('Retry-After')}; stop") from exc
                raise
        self.index.append({"path": str(path.resolve()), "sha256": digest(path), "url": url})
        return envelope["response"]

    def rpc(self, method, params):
        if method not in ("eth_chainId", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber"):
            raise ValueError("not an allowed read-only RPC method")
        value = self.request(ARB_RPC, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        if value is None:
            return None
        if "error" in value:
            raise ValueError(f"RPC error: {value['error']}")
        return value["result"]


def load_trace(db, txhash, own):
    row = db.execute("SELECT data FROM roots WHERE hash=? AND done=1", (txhash,)).fetchone()
    if row:
        path = Path(json.loads(row[0])["sourceResponse"])
        entries = json.loads(path.read_text()).get("transactions") or []
        for entry in entries:
            if entry["transaction"]["hash"] == txhash:
                return normalize(entry)
    return own.get(txhash)


def investigate(args):
    out = args.output_dir
    if out.resolve() == args.ledger_dir.resolve() or args.ledger_dir.resolve() in out.resolve().parents:
        raise ValueError("analysis output must be separate from collector output")
    out.mkdir(parents=True, exist_ok=True)
    dbpath = args.ledger_dir / "ledger.sqlite3"
    db = sqlite3.connect(f"file:{dbpath.resolve()}?mode=ro", uri=True)
    cases = [json.loads(r[0]) for r in db.execute('SELECT data FROM withdrawals WHERE json_array_length(json_extract(data,"$.internalIntentsAccountRoutes"))>0 ORDER BY root,receipt,action_index')]
    own = {}
    for path in sorted((out / "responses").glob("*.json")):
        for entry in json.loads(path.read_text()).get("transactions") or []:
            own[entry["transaction"]["hash"]] = normalize(entry)
    roots = {h for r in cases for route in r["internalIntentsAccountRoutes"] for h in route.get("nearTxHashes") or []}
    builder_roots = set()
    links = [json.loads(s) for s in (args.ledger_dir / "bridge-transfer-links.jsonl").read_text().splitlines() if s]
    for link in links:
        if link["intentsNearTransactionHash"] in {r["nearTransactionHash"] for r in cases}:
            builder_roots.update(x["nearTransactionHash"] for x in link["builderRequests"])
    roots |= builder_roots
    traces = {h: trace for h in roots if (trace := load_trace(db, h, own)) is not None}
    evidence = Evidence(out, args.fetch, args.max_http_calls, args.delay)
    errors = []
    stopped = None
    try:
        pending = sorted(roots - traces.keys())
        if args.fetch:
            for offset in range(0, len(pending), 20):
                if evidence.calls >= evidence.limit:
                    raise CheckpointStop("per-run HTTP limit reached")
                payload, path, online = fetch_batch(pending[offset:offset+20], out, args.delay, 30, 1)
                evidence.calls += int(online)
                for entry in payload["transactions"]:
                    trace = normalize(entry)
                    if trace["nearTransactionHash"] not in pending[offset:offset+20]:
                        raise ValueError("unrequested NEAR transaction returned")
                    traces[trace["nearTransactionHash"]] = trace
                print(f"funding roots traced={len(traces)}/{len(roots)}", flush=True)
        for i, case in enumerate(cases, 1):
            account = case["signedWithdrawalAccounts"][0]["intentsAccountId"]
            before = [r for r in case["internalIntentsAccountRoutes"] if route_before(r, case)]
            case["caseNumber"] = i
            case["routesBeforeWithdrawal"] = before
            case["routesAfterWithdrawal"] = [r for r in case["internalIntentsAccountRoutes"] if not route_before(r, case)]
            relevant = {h for route in case["internalIntentsAccountRoutes"] for h in route.get("nearTxHashes") or []}
            all_credits = [c for h in sorted(relevant) if h in traces for c in account_credits(traces[h], account)]
            credits, later, unknown = classify_credits(all_credits, case["blockTime"])
            case["verifiedIncomingZecEvents"] = credits
            case["laterIncomingZecEvents"] = later
            case["unknownTimeIncomingZecEvents"] = unknown
            case["incomingIntentsTransfers"] = [c for h in sorted(relevant) if h in traces for c in executed_intents_transfers(traces[h], account)]
            case["fundingRootsMissing"] = sorted(relevant - traces.keys())
            case["fundingRootReferenceErrors"] = [h for h in relevant if h in traces and not traces[h]["treeReferencesComplete"]]
            case["exactCreditAmountCount"] = sum(c["amountZat"] == case["requestedAmountZat"] for c in credits)
            case["bridgeLinks"] = [l for l in links if l["intentsNearTransactionHash"] == case["nearTransactionHash"]]
            addr = case["requestedReceiver"]
            case["addressPages"] = []
            if addr.startswith("t"):
                for page in range(1, args.max_address_pages + 1):
                    value = evidence.request(f"{ZEC_API}/address/{addr}?page={page}&limit=100")
                    if value is None:
                        break
                    case["addressPages"].append(value)
                    if not isinstance(value, dict):
                        raise ValueError("unexpected address response shape")
                    pagination = value.get("pagination") or {}
                    if pagination.get("hasNextPage") is False or pagination.get("hasNext") is False or (pagination.get("totalPages") is not None and page >= int(pagination["totalPages"])):
                        break
                    txs = value.get("transactions")
                    if isinstance(txs, list) and len(txs) < 100:
                        break
            for route in before:
                if not route.get("originAsset", "").startswith("nep141:arb-") or not route.get("originChainTxHashes") or not route.get("senders"):
                    continue
                h = route["originChainTxHashes"][0]
                chain = evidence.rpc("eth_chainId", [])
                tx = evidence.rpc("eth_getTransactionByHash", [h])
                receipt = evidence.rpc("eth_getTransactionReceipt", [h])
                if chain is None or tx is None or receipt is None:
                    continue
                if int(chain, 16) != 42161 or tx["hash"].lower() != h.lower() or receipt["transactionHash"].lower() != h.lower():
                    raise ValueError("RPC chain or transaction identity mismatch")
                block = evidence.rpc("eth_getBlockByNumber", [receipt["blockNumber"], False])
                canonical = block is not None and block["hash"].lower() == receipt["blockHash"].lower()
                token = route["originAsset"][len("nep141:arb-"):].split(".")[0]
                transfers = evm_transfers(receipt, token, route["senders"][0], route["depositAddress"])
                deposit_receipts = [d for root in route.get("nearTxHashes") or [] if root in traces
                                    for d in cross_chain_deposits(traces[root], h, 42161)]
                case["arbitrumDeposit"] = {"txid": h, "chainId": 42161, "sender": tx["from"],
                                           "successful": int(receipt["status"], 16) == 1, "canonical": canonical,
                                           "matchingTransfers": transfers, "expectedAmountRaw": route["amountIn"],
                                           "amountMatches": any(t["amountRaw"] == route["amountIn"] for t in transfers),
                                           "nearBridgeDepositReceipts": deposit_receipts,
                                           "depositMemoMatches": any(d["amountRaw"] == route["amountIn"] and d["token"] == "arb-" + token and d["ownerId"] == "intents.near" for d in deposit_receipts),
                                           "blockTime": datetime.fromtimestamp(int(block["timestamp"],16),timezone.utc).isoformat() if block else None,
                                           "warning": "This deposit funds the recorded Intents account route, not proof of the Challenge 7 private spend."}
            case["explicitPayoutIds"] = [p for link in case["bridgeLinks"] for request in link["builderRequests"] if request["nearTransactionHash"] in traces for p in pending_payouts(traces[request["nearTransactionHash"]])]
            case["builderPackets"] = [packet for link in case["bridgeLinks"] for request in link["builderRequests"] if request["nearTransactionHash"] in traces for packet in builder_packets(traces[request["nearTransactionHash"]])]
            candidates = []
            for page in case["addressPages"]:
                for tx in page.get("transactions") or []:
                    # A declared search window, not a unique or exhaustive link.
                    delta = int(tx["blockTime"]) * 1_000_000_000 - timestamp_ns(case["blockTime"])
                    if 0 <= delta <= 3600 * 1_000_000_000 and int(tx.get("outputValue") or 0) > 0:
                        candidates.append({"txid": tx["txid"], "addressSummary": tx,
                                           "evidenceClass": "receiver-and-time-candidate-NOT-a-NEAR-transaction-identity-link"})
            case["transparentPayoutCandidates"] = candidates
            wanted = {p["txid"] for p in case["explicitPayoutIds"] + candidates}
            # Also examine direct spends visible in the same complete address snapshot.
            wanted.update(tx["txid"] for page in case["addressPages"] for tx in page.get("transactions") or [] if int(tx.get("inputValue") or 0) > 0 and int(tx["blockHeight"]) <= 3488703)
            case["transactionDetails"] = {}
            for txid in sorted(wanted):
                detail = evidence.request(f"{ZEC_API}/tx/{txid}")
                if detail is not None:
                    case["transactionDetails"][txid] = detail
            case["rawPayoutVerification"] = []
            if len(case["builderPackets"]) == 1:
                for item in case["explicitPayoutIds"]:
                    raw = evidence.request(f"{ZEC_API}/tx/{item['txid']}/raw")
                    if raw is not None and args.decoder.exists():
                        packet = {"hex": raw["hex"], "expectedTxid": item["txid"]}
                        decoded = json.loads(subprocess.run([str(args.decoder.resolve())], input=json.dumps(packet)+"\n", text=True, capture_output=True, check=True, timeout=30).stdout)
                        case["rawPayoutVerification"].append({"decoded": decoded, "comparison": compare_raw_packet(case["builderPackets"][0], decoded)})
            if addr.startswith("u1"):
                # Supplemental public aggregate scan: not receiver attribution.
                # The start block is the first cached compact block at/after the
                # request's timestamp. One page is deliberately bounded.
                blocks = json.loads(args.early_compact.read_text()).get("blocks") or []
                eligible = [b for b in blocks if int(b["time"])*1_000_000_000 >= timestamp_ns(case["blockTime"])]
                if eligible:
                    start = min(int(b["height"]) for b in eligible)
                    end = start + 25
                    value = evidence.request(f"{ZEC_API}/shielded/list?cursor={end}&direction=next&flow_type=shield&pool=all&limit=100")
                    case["boundedShieldingWindow"] = {"fromHeight": start, "toHeight": end, "response": value,
                                                     "warning": "Block-time heuristic window, no shielded receiver or note identity link. Not an exhaustive delay bound."}
                    sampled = [b for b in blocks if start <= int(b["height"]) < start + args.early_probe_blocks]
                    case["earlyCompactProbe"] = {"fromHeight": start, "toHeightExclusive": start + args.early_probe_blocks,
                                                 "blockCount": len(sampled), "transactions": [],
                                                 "warning": "Complete shielded compact-transaction enumeration of this tiny block sample only, not a payout association or a full delay search."}
                    for block in sampled:
                        for tx in block.get("vtx") or []:
                            txid = normalize_hash(tx["hash"])
                            detail = cache_detail(args.summary_cache, txid) or evidence.request(f"{ZEC_API}/tx/{txid}")
                            if detail is not None:
                                case["earlyCompactProbe"]["transactions"].append(detail)
                    case["probeBudgetCandidates"] = []
                    for detail in case["earlyCompactProbe"]["transactions"]:
                        net = max(-int(detail.get("valueBalanceIronwoodZat") or 0), 0)
                        if 0 < net <= int(case["requestedAmountZat"]):
                            raw = evidence.request(f"{ZEC_API}/tx/{detail['txid']}/raw")
                            decoded = None
                            if raw is not None and args.decoder.exists():
                                packet = {"hex": raw["hex"], "expectedTxid": detail["txid"], "unifiedAddresses": [addr], "blockHeight": int(detail["blockHeight"]), "blockTime": detail["blockTime"], "isCanonical": detail.get("isCanonical")}
                                decoded = json.loads(subprocess.run([str(args.decoder.resolve())], input=json.dumps(packet)+"\n", text=True, capture_output=True, check=True, timeout=30).stdout)
                            case["probeBudgetCandidates"].append({"txid":detail["txid"], "netIronwoodInflowZat":net,
                                                                  "requestMinusNetZat":int(case["requestedAmountZat"])-net,
                                                                  "rawDecode":decoded, "warning":"Public aggregate and timing fit only; opaque outputs are not recovered notes or proven receiver matches."})
            # One additional public hop for the small Arbitrum-funded branch.
            if case.get("arbitrumDeposit"):
                recipients = {o["address"] for d in case["transactionDetails"].values()
                              if any(x.get("address") == addr for x in d.get("inputs") or [])
                              for o in d.get("outputs") or [] if o.get("address") and o["address"] != addr}
                case["nextTransparentAddressPages"] = {dest: evidence.request(f"{ZEC_API}/address/{dest}?page=1&limit=100") for dest in sorted(recipients)}
                case["publicSecondHopSpends"] = []
                starts = [(d["txid"], int(o["vout_index"]), o["address"], int(d["blockHeight"]))
                          for d in case["transactionDetails"].values() if any(x.get("address")==addr for x in d.get("inputs") or [])
                          for o in d.get("outputs") or [] if o.get("address") and o["address"] != addr]
                for source_txid, vout, dest, min_height in starts:
                    page = case["nextTransparentAddressPages"].get(dest) or {}
                    for tx in page.get("transactions") or []:
                        if int(tx.get("inputValue") or 0) <= 0 or not min_height <= int(tx["blockHeight"]) <= 3488703:
                            continue
                        detail = evidence.request(f"{ZEC_API}/tx/{tx['txid']}")
                        if detail and any(x.get("prev_txid")==source_txid and int(x["prev_vout"])==vout for x in detail.get("inputs") or []):
                            case["publicSecondHopSpends"].append({"sourceOutpoint":f"{source_txid}:{vout}", "detail":detail,
                                                               "warning":"Indexed public UTXO spend, not common ownership or attribution of pooled output values."})
            print(f"case={i} credits={len(credits)} missing_funding_roots={len(case['fundingRootsMissing'])} address_pages={len(case['addressPages'])}", flush=True)
    except (CheckpointStop, OSError, ValueError) as exc:
        stopped = str(exc)
        errors.append(stopped)
    finally:
        write_rows(out / "cases.jsonl", cases)
        write_rows(out / "funding-traces.jsonl", [traces[h] for h in sorted(traces)])
        manifest = {"createdAt": datetime.now(timezone.utc).isoformat(), "challengeSolved": False,
                    "inputWithdrawalSha256": digest(args.ledger_dir / "withdrawals.jsonl"),
                    "inputLinksSha256": digest(args.ledger_dir / "bridge-transfer-links.jsonl"),
                    "inputCollectorManifestSha256": digest(args.ledger_dir / "manifest.json"),
                    "casesSha256": digest(out / "cases.jsonl"), "fundingTracesSha256": digest(out / "funding-traces.jsonl"),
                    "scriptSha256": digest(Path(__file__)), "parserSha256": digest(Path(__file__).with_name("trace_challenge7_free_near.py")),
                    "cases": len(cases), "fundingRoots": len(roots), "tracedFundingRoots": len(traces),
                    "newHttpCalls": evidence.calls, "stopped": stopped, "errors": errors,
                    "httpResponses": evidence.index,
                    "allSavedHttpResponses": [{"path": str(p.resolve()), "sha256": digest(p)} for p in sorted((out / "http-responses").glob("*.json"))],
                    "nearResponses": [{"path":str(p.resolve()),"sha256":digest(p)} for p in sorted((out/"responses").glob("*.json"))]}
        manifest["decoderSha256"] = digest(args.decoder) if args.decoder.exists() else None
        dump(out / "manifest.json", manifest)
        db.close()
    print(f"done: {out}/cases.jsonl; stopped={stopped}", flush=True)
    return 2 if stopped else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-dir", type=Path, default=Path("challenge7-withdrawal-ledger-data"))
    parser.add_argument("--output-dir", type=Path, default=Path("challenge7-account-link-data"))
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--max-http-calls", type=int, default=40)
    parser.add_argument("--max-address-pages", type=int, default=2)
    parser.add_argument("--delay", type=float, default=3)
    parser.add_argument("--decoder", type=Path, default=Path("decoder/target/release/note_ledger"))
    parser.add_argument("--early-compact", type=Path, default=Path("challenge7-migration-data/compact/3428143-3430142.json"))
    parser.add_argument("--early-probe-blocks", type=int, default=2)
    parser.add_argument("--summary-cache", type=Path, default=Path("challenge7-payout-universe-data/cache/cipherscan-txns"))
    args = parser.parse_args()
    if args.delay < 1 or args.max_http_calls < 0 or not 1 <= args.max_address_pages <= 5 or not 0 <= args.early_probe_blocks <= 5:
        parser.error("delay >= 1, nonnegative HTTP limit, address pages 1..5, early probe blocks 0..5")
    return investigate(args)


if __name__ == "__main__":
    raise SystemExit(main())
