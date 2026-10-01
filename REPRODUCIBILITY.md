# Reproducibility notes

These commands query public protocol APIs and chain RPCs. They do not require private wallet
data. `curl` and `jq` are assumed; challenge 3 optionally uses Foundry's `cast`.

## Challenge 1 — Relay

Fetch every Relay request associated with the common source and select the challenge request:

```bash
SOURCE=0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A
REQUEST=0x17898153392c985f330b7fafd7f9dd196ff86acd63b39b07dcbe12b3e1700667

curl -sS "https://api.relay.link/requests/v2?user=$SOURCE" \
  | jq --arg request "$REQUEST" '.requests[] | select(.id == $request) | {
      id,
      status,
      user,
      recipient,
      createdAt,
      input: .data.metadata.currencyIn,
      output: .data.metadata.currencyOut,
      inTxs: [.data.inTxs[] | {chainId, hash, timestamp}],
      outTxs: [.data.outTxs[] | {chainId, hash, timestamp}]
    }'
```

Expected identifying fields:

```text
user      0x8d5a4fe39f7c4407431e48bd6bf727e5a159f98a
recipient 0x72cc4839fB181fe25e1F1eA8aDa1c497a7C07e7C
input     9.1 USDC on chain 42161
output    9.074557 USDC on chain 8453
```

Cross-check the request through Relay's status endpoint:

```bash
curl -sS "https://api.relay.link/intents/status/v3?requestId=$REQUEST" | jq
```

## Challenge 2 — STRK-20

### Recover the Starknet destination from Layerswap

```bash
LAYERSWAP_INPUT=0x0087eb3d2fabbd71c33f3c996129facd28eb0f20284dffaa51a55ba46705901c

curl -sS \
  "https://api.layerswap.io/api/v2/explorer/$LAYERSWAP_INPUT?version=prod&page=1&statuses=Completed&statuses=PendingWithdrawal&statuses=PendingRefund&statuses=Refunded" \
  | jq '.data[].swap | {
      id,
      source_address,
      destination_address,
      source_network: .source_network.name,
      destination_network: .destination_network.name,
      transactions: [.transactions[] | {
        type, transaction_hash, from, to, amount, timestamp
      }]
    }'
```

The response identifies Starknet account `0x04254b…aab7`, output transaction `0x07ab…3ec`,
and output amount `0.00380269 ETH`.

### Establish the one-member deposit set

Set `STARKNET_RPC_URL` to any Starknet JSON-RPC endpoint supporting `starknet_getEvents`:

```bash
export STARKNET_RPC_URL='https://your-starknet-rpc.example'
```

Then query the STRK-20 pool for `strkBTC` deposits in the relevant window:

```bash
curl -sS "$STARKNET_RPC_URL" \
  -H 'content-type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "starknet_getEvents",
    "params": {
      "filter": {
        "from_block": {"block_number": 15100000},
        "to_block": {"block_number": 15116601},
        "address": "0x40337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
        "keys": [
          ["0x9149d2123147c5f43d258257fef0b7b969db78269369ebcf5ebb9eef8592f2"],
          [],
          ["0x787150e306e6eae6e3f79dea881770e8bbff2c1b8eb490f969669ee945b3135"]
        ],
        "chunk_size": 100
      }
    }
  }' \
  | jq '{count: (.result.events | length), events: .result.events}'
```

Expected result: `count: 1`, transaction `0x434e…eba`, block `15,115,897`, and data
`0x2cec` (`11,500`). Starknet RPC responses omit leading zeroes from field elements; this is
why the addresses in the query are numerically identical to, but shorter than, the
zero-padded forms in the report.

The corresponding withdrawal receipt can be inspected with:

```bash
WITHDRAWAL=0x63522eda1a41c57ac3000b5b97d05bb6b68d196d25b0fb0abd577cf697e9e49

curl -sS "$STARKNET_RPC_URL" \
  -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getTransactionReceipt\",\"params\":{\"transaction_hash\":\"$WITHDRAWAL\"}}" \
  | jq '.result.events[] | select(.keys[0] == "0x2eed7e29b3502a726faf503ac4316b7101f3da813654e8df02c13449e03da8")'
```

Finally, inspect Starkgate transaction `0x33a9…615`; its calldata includes the Ethereum
destination and amount reported in [`CHALLENGE-2.md`](CHALLENGE-2.md).

## Challenge 3 — Zama confidential ERC-20

An Ethereum RPC returns the public input of the confidential transfer:

```bash
export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
TX=0x87555b02e16056c76a02267c8f247c1972fbd71adbcef8a0239cd92387f13857

INPUT=$(cast tx "$TX" input --rpc-url "$ETHEREUM_RPC_URL")
cast calldata-decode 'confidentialTransfer(address,bytes32,bytes)' "$INPUT"
```

Expected first argument:

```text
0x906ff67514449638DadDC09b007f0b7b3023EF33
```

The transaction receipt independently contains the source and destination as indexed topics.

## Challenge 4 — Payy

Probe the endpoints on which the explorer depends:

```bash
PAYY_API=https://validators.mainnet.payy.network/v0

curl -i "$PAYY_API/height"
curl -i "$PAYY_API/blocks/32791739"
curl -i "$PAYY_API/elements?elements=0x18986a83064e3a6a02ff4b1274dfe53d458c75bb054bfe12976f413a0369bb64&include_spent=true"
```

These returned HTTP 502 on 2026-09-30, and the block endpoint still returned 502 when rechecked
on 2026-10-01. When the service or a historical node mirror becomes available, run the
included graph walker:

```bash
python3 scripts/trace_payy.py
```

It will:

1. fetch block `32,791,739`;
2. identify the burn transaction by first input commitment;
3. resolve each commitment's creating transaction through the spent-aware `/elements` list
   endpoint and `/transactions`;
4. recursively print input/output edges; and
5. stop successfully when it reaches the mint transaction whose public message carries
   `0x143e78…0575`.

An alternate API or restored snapshot can be supplied with `--api`:

```bash
python3 scripts/trace_payy.py --api https://payy-node-mirror.example/v0
```

## Challenge 5 — Privacy Boost

Blockscout's log API can retrieve the full entrypoint history up to the target withdrawal
block (`507142770`):

```bash
ENTRYPOINT=0x44192215FEd782896BE2CE24E0Bfbf0BF825d15E
TARGET_BLOCK=507142770
DEPOSIT_TOPIC=0xf5681f9d0db1b911ac18ee83d515a1cf1051853a9eae418316a2fdf7dea427c5
WITHDRAWAL_TOPIC=0xe9b67844a7bb6e6ac95e8a0de02e4448dbb0c9460be9194348e4bbac6d13c2cf

curl -sS \
  "https://arbitrum.blockscout.com/api?module=logs&action=getLogs&fromBlock=0&toBlock=$TARGET_BLOCK&address=$ENTRYPOINT&topic0=$DEPOSIT_TOPIC" \
  > deposits.json

curl -sS \
  "https://arbitrum.blockscout.com/api?module=logs&action=getLogs&fromBlock=0&toBlock=$TARGET_BLOCK&address=$ENTRYPOINT&topic0=$WITHDRAWAL_TOPIC" \
  > withdrawals.json

jq '.result | length' deposits.json
jq '.result | length' withdrawals.json
```

Expected deployment-wide counts are 430 deposits and 531 withdrawals. Filter deposits to the
USDC pool and withdrawals to the USDC token:

```bash
POOL=3706e38af05bf0158bcdbb46239f8289980b093f
USDC=af88d065e77c8cc2239327c5edb3a432268e5831

jq --arg pool "$POOL" '[.result[] |
  select((.topics[2] // "") | ascii_downcase | endswith($pool))]' deposits.json \
  | jq 'length'

jq --arg usdc "$USDC" '[.result[] |
  select((.topics[3] // "") | ascii_downcase | endswith($usdc))]' withdrawals.json \
  | jq 'length'
```

Expected counts are 221 USDC-pool deposits and 287 USDC withdrawals. Each event's final
32-byte data word encodes its amount; convert the `0x` value to decimal before applying USDC's
six decimals.

## Challenge 6 — all-zero OVK

Challenge 6 has a purpose-built Rust reproduction utility. See
[`decoder/README.md`](decoder/README.md) for the command and expected output.
