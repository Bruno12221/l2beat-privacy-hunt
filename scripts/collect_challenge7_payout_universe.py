#!/usr/bin/env python3
"""Audit the complete NEAR Intents -> Zcash payout universe for Challenge 7.

This collector deliberately uses two independent discovery surfaces:

1. raw ``ft_on_transfer`` receipts sent to ``zcash-connector.bridge.near``;
2. an unfiltered NEAR Intents route export supplied with ``--routes``.

It downloads transaction details for the raw receipts, extracts the requested
Zcash receiver, reconciles those requests against explorer routes, and fetches
the public Orchard/Ironwood value balances for every route payout from
CipherScan. All stages are cached, resumable, and tolerate individual 404s.

The script does not pretend that an Orchard->Ironwood migration balance is a
single note. Its payout summaries describe direct bridge payouts only and can
be passed to ``solve_challenge7_note_budget.py``.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import random
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


NEARBLOCKS_API = "https://api.nearblocks.io/v3"
CIPHERSCAN_TX_API = "https://api.mainnet.cipherscan.app/api/tx"
NEAR_ARCHIVAL_RPC = "https://archival-rpc.mainnet.fastnear.com"
NEAR_RELAYER_ACCOUNT = "omni-relayer.bridge.near"
CONNECTOR_ACCOUNT = "zcash-connector.bridge.near"
CONNECTOR_METHOD = "ft_on_transfer"

# Account creation precedes the first contract deployment by about 17 minutes.
# Starting here avoids assuming the deployment lookup is itself exhaustive.
DEFAULT_SINCE = "2025-08-20T19:25:34.967208Z"
DEFAULT_UNTIL = "2026-09-19T10:01:11Z"


def utc(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_from_ns(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000_000, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (TypeError, ValueError, OSError):
        return None


def iso_from_epoch(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (TypeError, ValueError, OSError):
        return None


def integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def first(value: Any) -> str | None:
    values = value if isinstance(value, list) else [value]
    for item in values:
        if item:
            return str(item).removeprefix("0x").lower()
    return None


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    temporary.replace(path)


def dump_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    atomic_write(
        path,
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
    )


def append_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    """Append crawler pages without rewriting a potentially huge ledger file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def load_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        first_char = handle.read(1)
        handle.seek(0)
        if first_char == "[":
            value = json.load(handle)
            return [row for row in value if isinstance(row, dict)]
        return [json.loads(line) for line in handle if line.strip()]


def cache_name(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest() + ".json"


class HttpClient:
    def __init__(
        self,
        cache_dir: Path,
        timeout: float,
        attempts: int,
        delay: float,
        api_key: str | None,
    ) -> None:
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.attempts = attempts
        self.delay = delay
        self.api_key = api_key
        self._lock = threading.Lock()
        self._last_request = 0.0

    def json(self, url: str, group: str) -> Any:
        path = self.cache_dir / group / cache_name(url)
        if path.exists() and path.stat().st_size:
            return json.loads(path.read_text(encoding="utf-8"))
        path.parent.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []
        for attempt in range(1, self.attempts + 1):
            with self._lock:
                wait = self.delay - (time.monotonic() - self._last_request)
                if wait > 0:
                    time.sleep(wait)
                self._last_request = time.monotonic()
            headers = {
                "accept": "application/json",
                "user-agent": "l2beat-privacy-hunt-research/1.0",
            }
            if self.api_key and url.startswith(NEARBLOCKS_API):
                headers["authorization"] = f"Bearer {self.api_key}"
                headers["x-api-key"] = self.api_key
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = response.read().decode("utf-8")
                value = json.loads(payload)
                atomic_write(path, json.dumps(value, sort_keys=True) + "\n")
                return value
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise FileNotFoundError(f"HTTP 404 for {url}") from exc
                errors.append(f"attempt {attempt}: HTTP {exc.code}")
                retry_after = exc.headers.get("Retry-After")
                try:
                    server_wait = float(retry_after) if retry_after else 0.0
                except ValueError:
                    server_wait = 0.0
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                errors.append(f"attempt {attempt}: {exc}")
                server_wait = 0.0
            if attempt < self.attempts:
                backoff = min(60.0, 2 ** (attempt - 1) * 2.0)
                time.sleep(max(backoff, server_wait) + random.random())
        raise RuntimeError(f"request failed for {url}: {'; '.join(errors)}")

    def rpc_json(
        self,
        url: str,
        payload: dict[str, Any],
        group: str,
        cache_key: str,
    ) -> Any:
        path = self.cache_dir / group / f"{cache_key}.json"
        if path.exists() and path.stat().st_size:
            return json.loads(path.read_text(encoding="utf-8"))
        path.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        errors: list[str] = []
        for attempt in range(1, self.attempts + 1):
            with self._lock:
                wait = self.delay - (time.monotonic() - self._last_request)
                if wait > 0:
                    time.sleep(wait)
                self._last_request = time.monotonic()
            headers = {
                "content-type": "application/json",
                "accept": "application/json",
                "user-agent": "l2beat-privacy-hunt-research/1.0",
            }
            if self.api_key:
                headers["authorization"] = f"Bearer {self.api_key}"
            request = urllib.request.Request(url, data=body, headers=headers)
            server_wait = 0.0
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    value = json.loads(response.read().decode("utf-8"))
                rpc_error = value.get("error") if isinstance(value, dict) else None
                if rpc_error:
                    code = rpc_error.get("code") if isinstance(rpc_error, dict) else None
                    message = (
                        rpc_error.get("message")
                        if isinstance(rpc_error, dict)
                        else str(rpc_error)
                    )
                    if code == -429 or "rate limit" in str(message).lower():
                        raise urllib.error.HTTPError(
                            url, 429, str(message), {}, None
                        )
                    raise RuntimeError(f"RPC error {code}: {message}")
                atomic_write(path, json.dumps(value, sort_keys=True) + "\n")
                return value
            except urllib.error.HTTPError as exc:
                errors.append(f"attempt {attempt}: HTTP {exc.code}")
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    server_wait = float(retry_after) if retry_after else 0.0
                except ValueError:
                    server_wait = 0.0
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                errors.append(f"attempt {attempt}: {exc}")
            except RuntimeError as exc:
                # UNKNOWN_TRANSACTION and malformed requests are not made
                # healthier by hammering the provider six times.
                raise RuntimeError(f"request failed for {cache_key}: {exc}") from exc
            if attempt < self.attempts:
                backoff = min(30.0, 2 ** (attempt - 1))
                time.sleep(max(backoff, server_wait) + random.random())
        raise RuntimeError(
            f"RPC request failed for {cache_key}: {'; '.join(errors)}"
        )


def route_txid(route: dict[str, Any]) -> str | None:
    return first(route.get("destinationChainTxHashes")) or first(
        route.get("zcashPayoutTxid")
    )


def route_created(route: dict[str, Any]) -> str | None:
    value = route.get("createdAt")
    return str(value) if value else None


def route_summary(route: dict[str, Any], txid: str, tx: dict[str, Any]) -> dict[str, Any]:
    orchard_balance = integer(tx.get("valueBalanceOrchardZat")) or 0
    ironwood_balance = integer(tx.get("valueBalanceIronwoodZat")) or 0
    reported = integer(route.get("amountOut")) or integer(route.get("rawAmountOut"))
    if reported is None and route.get("amountOutFormatted") is not None:
        try:
            reported = round(float(route["amountOutFormatted"]) * 100_000_000)
        except (TypeError, ValueError):
            pass
    return {
        "createdAt": route_created(route),
        "blockTime": iso_from_epoch(tx.get("blockTime")),
        "zcashBlockHeight": integer(tx.get("blockHeight")),
        "zcashPayoutTxid": txid,
        "actualOrchardValueCreatedZat": max(-orchard_balance, 0),
        "actualIronwoodValueCreatedZat": max(-ironwood_balance, 0),
        "valueBalanceOrchardZat": orchard_balance,
        "valueBalanceIronwoodZat": ironwood_balance,
        "feeZat": integer(tx.get("feeZat")),
        "orchardActions": integer(tx.get("orchardActions")),
        "ironwoodActions": integer(tx.get("ironwoodActions")),
        "recipient": route.get("recipient"),
        "referral": route.get("referral"),
        "originAsset": route.get("originAsset"),
        "depositAddress": route.get("depositAddress"),
        "refundAddress": route.get("refundTo") or route.get("refundAddress"),
        "sourceTxHash": first(route.get("originChainTxHashes"))
        or route.get("sourceTxHash"),
        "sourceSenders": route.get("senders") or route.get("sourceSenders") or [],
        "reportedAmountOutZat": reported,
        "cipherscanUrl": f"https://cipherscan.app/tx/{txid}",
    }


def decode_nested_json(value: Any) -> dict[str, Any] | None:
    current = value
    for _ in range(6):
        if isinstance(current, dict):
            return current
        if not isinstance(current, str):
            return None
        try:
            current = json.loads(current)
            continue
        except json.JSONDecodeError:
            # NearBlocks returns this argument with two extra escaping layers.
            # The payload is JSON/base64 only; decode one backslash layer and
            # retry rather than evaluating it as code.
            try:
                current = current.encode("utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                return None
    return current if isinstance(current, dict) else None


def normalize_raw_detail(
    receipt: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any]:
    tx = response.get("data") if isinstance(response.get("data"), dict) else response
    outer: dict[str, Any] = {}
    for action in tx.get("actions") or []:
        if action.get("method") == "submit_transfer_to_utxo_chain_connector":
            args = action.get("args") or {}
            candidate = args.get("args_json") or {}
            if isinstance(candidate, dict):
                outer = candidate
                break
    message = decode_nested_json(outer.get("msg")) or {}
    withdraw = message.get("Withdraw") if isinstance(message.get("Withdraw"), dict) else {}
    transfer_id = outer.get("transfer_id") if isinstance(outer.get("transfer_id"), dict) else {}
    block = receipt.get("block") if isinstance(receipt.get("block"), dict) else {}
    timestamp_ns = block.get("block_timestamp") or receipt.get("included_in_block_timestamp")
    return {
        "nearTransactionHash": receipt.get("transaction_hash"),
        "receiptId": receipt.get("receipt_id"),
        "blockHeight": integer(block.get("block_height")),
        "blockTimestampNs": str(timestamp_ns) if timestamp_ns is not None else None,
        "blockTime": iso_from_ns(timestamp_ns),
        "predecessorAccountId": receipt.get("predecessor_account_id"),
        "targetAddress": withdraw.get("target_btc_address"),
        "transparentOutputs": withdraw.get("output") or [],
        "connectorInputs": withdraw.get("input") or [],
        "maxGasFee": integer(withdraw.get("max_gas_fee")),
        "expiryHeight": integer(
            withdraw.get("expiry_height")
            or (
                (withdraw.get("chain_specific_data") or {}).get("expiry_height")
                if isinstance(withdraw.get("chain_specific_data"), dict)
                else None
            )
        ),
        "transferOriginChain": transfer_id.get("origin_chain"),
        "transferOriginNonce": transfer_id.get("origin_nonce"),
        "parseOk": bool(withdraw.get("target_btc_address")),
    }


def normalize_raw_rpc_detail(
    receipt: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any]:
    result = response.get("result") if isinstance(response.get("result"), dict) else {}
    transaction = (
        result.get("transaction") if isinstance(result.get("transaction"), dict) else {}
    )
    outer: dict[str, Any] = {}
    for action in transaction.get("actions") or []:
        function_call = action.get("FunctionCall") if isinstance(action, dict) else None
        if not isinstance(function_call, dict):
            continue
        if function_call.get("method_name") != "submit_transfer_to_utxo_chain_connector":
            continue
        encoded = function_call.get("args")
        if not isinstance(encoded, str):
            continue
        try:
            decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid NEAR function-call args: {exc}") from exc
        if isinstance(decoded, dict):
            outer = decoded
            break
    message = decode_nested_json(outer.get("msg")) or {}
    withdraw = message.get("Withdraw") if isinstance(message.get("Withdraw"), dict) else {}
    transfer_id = outer.get("transfer_id") if isinstance(outer.get("transfer_id"), dict) else {}
    block = receipt.get("block") if isinstance(receipt.get("block"), dict) else {}
    timestamp_ns = block.get("block_timestamp") or receipt.get("included_in_block_timestamp")
    chain_data = (
        withdraw.get("chain_specific_data")
        if isinstance(withdraw.get("chain_specific_data"), dict)
        else {}
    )
    return {
        "nearTransactionHash": receipt.get("transaction_hash"),
        "receiptId": receipt.get("receipt_id"),
        "blockHeight": integer(block.get("block_height")),
        "blockTimestampNs": str(timestamp_ns) if timestamp_ns is not None else None,
        "blockTime": iso_from_ns(timestamp_ns),
        "predecessorAccountId": receipt.get("predecessor_account_id"),
        "targetAddress": withdraw.get("target_btc_address"),
        "transparentOutputs": withdraw.get("output") or [],
        "connectorInputs": withdraw.get("input") or [],
        "maxGasFee": integer(withdraw.get("max_gas_fee")),
        "expiryHeight": integer(
            withdraw.get("expiry_height") or chain_data.get("expiry_height")
        ),
        "transferOriginChain": transfer_id.get("origin_chain"),
        "transferOriginNonce": transfer_id.get("origin_nonce"),
        "parseOk": bool(withdraw.get("target_btc_address")),
        "detailSource": "near-archival-rpc",
    }


def collect_raw_receipts(
    args: argparse.Namespace, client: HttpClient, output: Path, state: dict[str, Any]
) -> list[dict[str, Any]]:
    path = output / "raw-near-receipts.jsonl"
    receipts = load_records(path)
    by_id = {str(row.get("receipt_id")): row for row in receipts if row.get("receipt_id")}
    if state.get("rawListingComplete"):
        return list(by_id.values())

    since_ns = int(utc(args.since).timestamp() * 1_000_000_000)
    until_ns = int(utc(args.until).timestamp() * 1_000_000_000)
    cursor = state.get("rawNextPage")
    page_number = int(state.get("rawPagesCompleted", 0))
    while True:
        if args.max_raw_pages and page_number >= args.max_raw_pages:
            break
        params: dict[str, Any] = {
            "method": CONNECTOR_METHOD,
            "before_ts": until_ns,
            "limit": args.raw_page_size,
        }
        if cursor:
            params["next"] = cursor
        url = (
            f"{NEARBLOCKS_API}/accounts/{CONNECTOR_ACCOUNT}/receipts?"
            + urllib.parse.urlencode(params)
        )
        response = client.json(url, "nearblocks-receipt-pages")
        batch = response.get("data") or []
        if not isinstance(batch, list):
            raise RuntimeError("NearBlocks receipt response has no data array")
        newly_retained: list[dict[str, Any]] = []
        for row in batch:
            if not isinstance(row, dict):
                continue
            block = row.get("block") or {}
            timestamp = integer(block.get("block_timestamp"))
            if timestamp is not None and since_ns <= timestamp <= until_ns:
                receipt_id = str(row.get("receipt_id"))
                if receipt_id not in by_id:
                    by_id[receipt_id] = row
                    newly_retained.append(row)
        page_number += 1
        timestamps = [
            integer((row.get("block") or {}).get("block_timestamp"))
            for row in batch
            if isinstance(row, dict)
        ]
        timestamps = [value for value in timestamps if value is not None]
        oldest = min(timestamps) if timestamps else None
        newest = max(timestamps) if timestamps else None
        cursor = (response.get("meta") or {}).get("next_page")
        complete = not batch or not cursor or (oldest is not None and oldest < since_ns)
        state.update(
            {
                "rawPagesCompleted": page_number,
                "rawNextPage": cursor,
                "rawListingComplete": complete,
                "rawReceiptCount": len(by_id),
            }
        )
        # Pagination is monotonic and receipt IDs are unique. Appending makes
        # this O(total rows), rather than repeatedly rewriting all prior pages.
        append_jsonl(path, newly_retained)
        receipts = list(by_id.values())
        dump_json(output / "state.json", state)
        print(
            f"raw page={page_number} rows={len(batch)} retained={len(receipts)} "
            f"newest={iso_from_ns(newest)} oldest={iso_from_ns(oldest)}",
            flush=True,
        )
        if complete:
            break
    return sorted(
        by_id.values(),
        key=lambda row: str((row.get("block") or {}).get("block_timestamp") or ""),
    )


def enrich_raw_receipts(
    args: argparse,
    nearblocks_client: HttpClient,
    rpc_client: HttpClient,
    output: Path,
    receipts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalized_path = output / "raw-withdrawals.jsonl"
    errors_path = output / "raw-detail-errors.json"
    normalized = {
        str(row.get("nearTransactionHash")): row
        for row in load_records(normalized_path)
        if row.get("nearTransactionHash")
    }
    errors = {
        str(row.get("nearTransactionHash")): row
        for row in load_records(errors_path)
        if row.get("nearTransactionHash")
    }
    pending = [
        row
        for row in receipts
        if row.get("transaction_hash")
        and str(row["transaction_hash"]) not in normalized
        and (
            str(row["transaction_hash"]) not in errors
            or "HTTP 404" not in str(errors[str(row["transaction_hash"])].get("error"))
        )
    ]
    if args.max_raw_details:
        pending = pending[: args.max_raw_details]

    def fetch(receipt: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        txhash = str(receipt["transaction_hash"])
        try:
            if args.raw_detail_source == "rpc":
                response = rpc_client.rpc_json(
                    args.near_rpc_url,
                    {
                        "jsonrpc": "2.0",
                        "id": txhash,
                        "method": "tx",
                        "params": {
                            "tx_hash": txhash,
                            "sender_account_id": args.near_rpc_signer,
                            "wait_until": "NONE",
                        },
                    },
                    "near-archival-rpc-txns",
                    txhash,
                )
                return "ok", normalize_raw_rpc_detail(receipt, response)
            response = nearblocks_client.json(
                f"{NEARBLOCKS_API}/txns/{txhash}", "nearblocks-txns"
            )
            return "ok", normalize_raw_detail(receipt, response)
        except Exception as exc:  # keep the full audit running on isolated failures
            return "error", {"nearTransactionHash": txhash, "error": str(exc)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.raw_workers) as executor:
        for index, (status, row) in enumerate(executor.map(fetch, pending), start=1):
            key = str(row["nearTransactionHash"])
            if status == "ok":
                normalized[key] = row
                errors.pop(key, None)
            else:
                errors[key] = row
            if index % 25 == 0 or index == len(pending):
                print(
                    f"raw details={index}/{len(pending)} total={len(normalized)} "
                    f"errors={len(errors)}",
                    flush=True,
                )
                write_jsonl(
                    normalized_path,
                    sorted(normalized.values(), key=lambda item: item.get("blockTime") or ""),
                )
                dump_json(errors_path, list(errors.values()))
    return list(normalized.values()), list(errors.values())


def priority_txids(path: Path) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for row in load_records(path):
        notes = row.get("notes") or []
        for note in notes:
            txid = first(note.get("zcashPayoutTxid")) if isinstance(note, dict) else None
            if txid and txid not in seen:
                seen.add(txid)
                ordered.append(txid)
    return ordered


def collect_payout_summaries(
    args: argparse,
    client: HttpClient,
    output: Path,
    routes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summary_path = output / "payout-summaries.jsonl"
    errors_path = output / "payout-errors.json"
    summaries = {
        str(row.get("zcashPayoutTxid")): row
        for row in load_records(summary_path)
        if row.get("zcashPayoutTxid")
    }
    errors = {
        str(row.get("zcashPayoutTxid")): row
        for row in load_records(errors_path)
        if row.get("zcashPayoutTxid")
    }
    route_by_txid: dict[str, dict[str, Any]] = {}
    for route in routes:
        txid = route_txid(route)
        if txid:
            route_by_txid.setdefault(txid, route)

    ordered: list[str] = []
    seen: set[str] = set()
    if args.priority_candidates.exists():
        for txid in priority_txids(args.priority_candidates):
            if txid in route_by_txid and txid not in seen:
                seen.add(txid)
                ordered.append(txid)
    for txid in sorted(route_by_txid):
        if txid not in seen:
            seen.add(txid)
            ordered.append(txid)
    pending = [
        txid
        for txid in ordered
        if txid not in summaries
        and (txid not in errors or "HTTP 404" not in str(errors[txid].get("error")))
    ]
    if args.max_payouts:
        pending = pending[: args.max_payouts]

    def fetch(txid: str) -> tuple[str, dict[str, Any]]:
        try:
            tx = client.json(f"{CIPHERSCAN_TX_API}/{txid}", "cipherscan-txns")
            return "ok", route_summary(route_by_txid[txid], txid, tx)
        except Exception as exc:
            route = route_by_txid[txid]
            return "error", {
                "zcashPayoutTxid": txid,
                "createdAt": route_created(route),
                "recipient": route.get("recipient"),
                "error": str(exc),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.payout_workers) as executor:
        for index, (status, row) in enumerate(executor.map(fetch, pending), start=1):
            key = str(row["zcashPayoutTxid"])
            if status == "ok":
                summaries[key] = row
                errors.pop(key, None)
            else:
                errors[key] = row
            if index % 100 == 0 or index == len(pending):
                print(
                    f"payout summaries={index}/{len(pending)} total={len(summaries)} "
                    f"errors={len(errors)}",
                    flush=True,
                )
                write_jsonl(
                    summary_path,
                    sorted(summaries.values(), key=lambda item: item.get("blockTime") or ""),
                )
                dump_json(errors_path, list(errors.values()))
    return list(summaries.values()), list(errors.values())


def reconcile(
    raw: list[dict[str, Any]], routes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    routes_by_recipient: dict[str, list[dict[str, Any]]] = {}
    for route in routes:
        recipient = route.get("recipient")
        if recipient:
            routes_by_recipient.setdefault(str(recipient), []).append(route)

    results: list[dict[str, Any]] = []
    for withdrawal in raw:
        receiver = str(withdrawal.get("targetAddress") or "")
        candidates = routes_by_recipient.get(receiver, [])
        raw_time = utc(str(withdrawal["blockTime"])) if withdrawal.get("blockTime") else None
        ranked: list[tuple[float, dict[str, Any]]] = []
        for route in candidates:
            created = route_created(route)
            if raw_time is None or not created:
                delta = float("inf")
            else:
                delta = abs((raw_time - utc(created)).total_seconds())
            ranked.append((delta, route))
        ranked.sort(key=lambda item: item[0])
        best_delta, best = ranked[0] if ranked else (None, None)
        results.append(
            {
                **withdrawal,
                "routeMatchCount": len(ranked),
                "routeMatchStatus": (
                    "missing" if not ranked else "unique" if len(ranked) == 1 else "ambiguous"
                ),
                "closestRouteTimeDeltaSeconds": best_delta,
                "matchedRouteCreatedAt": route_created(best) if best else None,
                "matchedZcashPayoutTxid": route_txid(best) if best else None,
                "matchedDepositAddress": best.get("depositAddress") if best else None,
            }
        )
    return sorted(results, key=lambda row: row.get("blockTime") or "")


def report_text(
    args: argparse,
    routes: list[dict[str, Any]],
    raw_receipts: list[dict[str, Any]],
    raw: list[dict[str, Any]],
    raw_errors: list[dict[str, Any]],
    reconciliation: list[dict[str, Any]],
    payouts: list[dict[str, Any]],
    payout_errors: list[dict[str, Any]],
) -> str:
    unique = sum(row["routeMatchStatus"] == "unique" for row in reconciliation)
    ambiguous = sum(row["routeMatchStatus"] == "ambiguous" for row in reconciliation)
    missing = sum(row["routeMatchStatus"] == "missing" for row in reconciliation)
    parsed = sum(bool(row.get("parseOk")) for row in raw)
    lines = [
        "# Challenge 7 payout-universe audit",
        "",
        f"- Window: `{args.since}` through `{args.until}`",
        f"- Explorer routes loaded: `{len(routes):,}`",
        f"- Explorer routes with a Zcash txid: `{sum(route_txid(r) is not None for r in routes):,}`",
        f"- Raw connector receipts found: `{len(raw_receipts):,}`",
        f"- Raw withdrawal details fetched: `{len(raw):,}`",
        f"- Raw target addresses decoded: `{parsed:,}`",
        f"- Raw-detail errors: `{len(raw_errors):,}`",
        f"- Unique recipient matches: `{unique:,}`",
        f"- Ambiguous recipient matches: `{ambiguous:,}`",
        f"- Missing recipient matches: `{missing:,}`",
        f"- Exact CipherScan payout summaries: `{len(payouts):,}`",
        f"- CipherScan payout errors: `{len(payout_errors):,}`",
        "",
        "## Completeness rule",
        "",
        "The explorer inventory is not considered complete merely because its crawler ended.",
        "Every decoded raw connector receiver should reconcile to an explorer route, subject to",
        "documented parser/API errors. Missing and ambiguous rows remain in `reconciliation.jsonl`",
        "for inspection. The exact note solver should only be treated as a full-universe pass when",
        "the raw listing is complete, all raw details have been attempted, and each route payout",
        "has either a CipherScan summary or an explicit error record.",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--routes", type=Path, default=Path("challenge7-complete-routes/all_routes.jsonl")
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("challenge7-payout-universe-data")
    )
    parser.add_argument("--since", default=DEFAULT_SINCE)
    parser.add_argument("--until", default=DEFAULT_UNTIL)
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="legacy override applied to both raw and payout workers",
    )
    parser.add_argument("--raw-workers", type=int, default=4)
    parser.add_argument("--payout-workers", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="minimum delay between CipherScan requests",
    )
    parser.add_argument(
        "--nearblocks-delay",
        type=float,
        default=1.25,
        help="minimum delay between NearBlocks requests (unauthenticated-safe default)",
    )
    parser.add_argument(
        "--raw-detail-source",
        choices=("rpc", "nearblocks"),
        default="rpc",
        help="fetch raw transaction actions from archival RPC by default",
    )
    parser.add_argument("--near-rpc-url", default=NEAR_ARCHIVAL_RPC)
    parser.add_argument("--near-rpc-signer", default=NEAR_RELAYER_ACCOUNT)
    parser.add_argument(
        "--near-rpc-api-key-env",
        default="FASTNEAR_API_KEY",
        help="optional environment variable for higher FastNEAR archival limits",
    )
    parser.add_argument("--raw-page-size", type=int, default=100)
    parser.add_argument("--max-raw-pages", type=int, default=0)
    parser.add_argument("--max-raw-details", type=int, default=0)
    parser.add_argument("--max-payouts", type=int, default=0)
    parser.add_argument("--skip-raw", action="store_true")
    parser.add_argument(
        "--skip-raw-details",
        action="store_true",
        help="collect the raw receipt inventory without fetching each transaction",
    )
    parser.add_argument("--skip-payouts", action="store_true")
    parser.add_argument(
        "--priority-candidates",
        type=Path,
        default=Path("challenge7-note-budget-data/clustered-pair-candidates.json"),
    )
    parser.add_argument(
        "--nearblocks-api-key-env",
        default="NEARBLOCKS_API_KEY",
        help="optional environment variable for a NearBlocks API key",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.workers is not None:
        args.raw_workers = args.workers
        args.payout_workers = args.workers
    if args.raw_workers < 1 or args.payout_workers < 1:
        raise SystemExit("worker counts must be positive")
    if not 1 <= args.raw_page_size <= 100:
        raise SystemExit("--raw-page-size must be between 1 and 100")
    if utc(args.since) >= utc(args.until):
        raise SystemExit("--since must be before --until")

    import os

    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    state_path = output / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    nearblocks_client = HttpClient(
        output / "cache",
        args.timeout,
        args.attempts,
        args.nearblocks_delay,
        os.environ.get(args.nearblocks_api_key_env),
    )
    cipherscan_client = HttpClient(
        output / "cache",
        args.timeout,
        args.attempts,
        args.delay,
        None,
    )
    rpc_client = HttpClient(
        output / "cache",
        args.timeout,
        args.attempts,
        0.0,
        os.environ.get(args.near_rpc_api_key_env),
    )
    routes = load_records(args.routes)
    if not routes and not args.skip_payouts:
        raise SystemExit(f"route file is missing or empty: {args.routes}")

    raw_receipts = load_records(output / "raw-near-receipts.jsonl")
    raw = load_records(output / "raw-withdrawals.jsonl")
    raw_errors = load_records(output / "raw-detail-errors.json")
    if not args.skip_raw:
        raw_receipts = collect_raw_receipts(args, nearblocks_client, output, state)
        if not args.skip_raw_details:
            raw, raw_errors = enrich_raw_receipts(
                args, nearblocks_client, rpc_client, output, raw_receipts
            )

    payouts = load_records(output / "payout-summaries.jsonl")
    payout_errors = load_records(output / "payout-errors.json")
    if not args.skip_payouts:
        payouts, payout_errors = collect_payout_summaries(
            args, cipherscan_client, output, routes
        )

    reconciliation = reconcile(raw, routes)
    write_jsonl(output / "reconciliation.jsonl", reconciliation)
    config = {
        "routes": str(args.routes),
        "since": args.since,
        "until": args.until,
        "connectorAccount": CONNECTOR_ACCOUNT,
        "connectorMethod": CONNECTOR_METHOD,
        "routeCount": len(routes),
        "rawReceiptCount": len(raw_receipts),
        "rawDetailCount": len(raw),
        "rawDetailErrorCount": len(raw_errors),
        "payoutSummaryCount": len(payouts),
        "payoutErrorCount": len(payout_errors),
        "rawListingComplete": bool(state.get("rawListingComplete")),
    }
    dump_json(output / "config.json", config)
    atomic_write(
        output / "report.md",
        report_text(
            args,
            routes,
            raw_receipts,
            raw,
            raw_errors,
            reconciliation,
            payouts,
            payout_errors,
        ),
    )
    print(
        f"done output={output} routes={len(routes)} raw_receipts={len(raw_receipts)} "
        f"raw_details={len(raw)} payouts={len(payouts)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
