#!/usr/bin/env python3
"""Trace challenge 4's public Payy commitment graph when the API is available.

The script uses only Python's standard library. It starts at the public burn block,
finds the burn transaction whose first input is the burn hash, and recursively
resolves the transactions that created its input commitments. It stops when it
finds the mint transaction carrying the known Ethereum mint hash.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any


DEFAULT_API = "https://validators.mainnet.payy.network/v0"
DEFAULT_MINT_HASH = (
    "0x143e784fb4aeeee1b5eaf6cb27f4a05c59e0f760e66edff8f2e01e8897760575"
)
DEFAULT_BURN_HASH = (
    "0x18986a83064e3a6a02ff4b1274dfe53d458c75bb054bfe12976f413a0369bb64"
)
DEFAULT_BURN_HEIGHT = 32_791_739


def normalize(value: str) -> str:
    """Normalize a field element without changing its numeric value."""
    return f"0x{int(value, 16):x}"


def public_inputs(txn: dict[str, Any]) -> dict[str, Any]:
    return txn["proof"]["public_inputs"]


def field_values(values: Iterable[str]) -> list[str]:
    return [normalize(value) for value in values]


class PayyClient:
    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get(self, path: str, query: dict[str, str] | None = None) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(
            url,
            headers={"accept": "application/json", "user-agent": "payy-trace/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GET {url} returned HTTP {error.code}: {body[:300]}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"GET {url} failed: {error.reason}") from error

    def block(self, height: int) -> dict[str, Any]:
        return self.get(f"blocks/{height}")

    def transaction(self, txn_hash: str) -> dict[str, Any]:
        response = self.get(f"transactions/{txn_hash}")
        return response.get("txn", response)

    def creating_transaction_hash(self, commitment: str) -> str:
        response = self.get(
            "elements",
            {"elements": commitment, "include_spent": "true"},
        )
        if not response:
            raise RuntimeError(f"commitment not found: {commitment}")
        return response[0]["txn_hash"]


def block_transactions(block_response: dict[str, Any]) -> list[dict[str, Any]]:
    return block_response["block"]["content"]["state"]["txns"]


def find_burn_transaction(
    txns: list[dict[str, Any]], burn_hash: str
) -> dict[str, Any]:
    target = normalize(burn_hash)
    for txn in txns:
        inputs = field_values(public_inputs(txn)["input_commitments"])
        if inputs and inputs[0] == target:
            return txn
    raise RuntimeError(
        f"burn commitment {burn_hash} was not input 0 of any transaction in the burn block"
    )


def transaction_is_source_mint(txn: dict[str, Any], mint_hash: str) -> bool:
    messages = field_values(public_inputs(txn).get("messages", []))
    if len(messages) < 4:
        return False
    return int(messages[0], 16) == 2 and messages[3] == normalize(mint_hash)


def trace_commitment(
    client: PayyClient,
    commitment: str,
    mint_hash: str,
    seen: set[str],
    depth: int = 0,
) -> bool:
    normalized = normalize(commitment)
    indent = "  " * depth
    if int(normalized, 16) == 0:
        print(f"{indent}- zero input")
        return False
    if normalized in seen:
        print(f"{indent}- {normalized} (already visited)")
        return False
    seen.add(normalized)

    creator_hash = client.creating_transaction_hash(normalized)
    creator = client.transaction(creator_hash)
    inputs = field_values(public_inputs(creator)["input_commitments"])
    outputs = field_values(public_inputs(creator)["output_commitments"])
    print(f"{indent}- commitment: {normalized}")
    print(f"{indent}  created_by: {creator_hash}")
    print(f"{indent}  block_height: {creator.get('block_height')}")
    print(f"{indent}  inputs: {json.dumps(inputs)}")
    print(f"{indent}  outputs: {json.dumps(outputs)}")

    if transaction_is_source_mint(creator, mint_hash):
        print(f"{indent}  SOURCE MINT FOUND: {normalize(mint_hash)}")
        return True

    found = False
    for input_commitment in inputs:
        found = (
            trace_commitment(
                client, input_commitment, mint_hash, seen, depth + 1
            )
            or found
        )
    return found


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=DEFAULT_API, help="Payy API base URL")
    parser.add_argument("--mint-hash", default=DEFAULT_MINT_HASH)
    parser.add_argument("--burn-hash", default=DEFAULT_BURN_HASH)
    parser.add_argument("--burn-height", type=int, default=DEFAULT_BURN_HEIGHT)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = PayyClient(args.api, args.timeout)
    try:
        txns = block_transactions(client.block(args.burn_height))
        burn_txn = find_burn_transaction(txns, args.burn_hash)
        burn_inputs = field_values(public_inputs(burn_txn)["input_commitments"])
        print(f"burn_transaction: {burn_txn['hash']}")
        print(f"burn_block_height: {args.burn_height}")
        print(f"burn_inputs: {json.dumps(burn_inputs)}")
        found = trace_commitment(
            client, args.burn_hash, args.mint_hash, seen=set()
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if not found:
        print("source mint was not reached", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
