# Challenge 4 — Payy

## Answer

- Challenge destination: [`0xc6F4Ad525be064C2ACB28b033231A00BBDdC33ab`](https://etherscan.io/address/0xc6F4Ad525be064C2ACB28b033231A00BBDdC33ab)
- Common source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://etherscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Route: Ethereum USDC → Payy mint → private Payy note graph → Payy burn → Ethereum USDC
- Evidence class: exact public ingress and egress; intermediate commitment list blocked by the unavailable Payy API

## Public ingress

At 2026-09-19 10:41:11, the source sends `9.067 USDC` to one-time Payy deposit address
`0x1F3c1031c7b8b7d9fEECD5CCeDC4f115c2eF952c`:

- [Ethereum transaction `0x17df…432`](https://etherscan.io/tx/0x17dfcd3894459692d6ab1afc6989fbd08cef19f4c5e3e03d9098abf68e645432)

Twelve seconds later, Payy's relayer calls `mintWithAuthorization` on RollupV1 proxy
`0x367C1eAF14AA06b78ce76bd0243297de79d85270`:

- [Mint transaction `0xe5dd…475`](https://etherscan.io/tx/0xe5ddccefbda4a889ec509a6e23d55cdc86353265bd1cfea546b641545d022547)
- Mint hash: `0x143e784fb4aeeee1b5eaf6cb27f4a05c59e0f760e66edff8f2e01e8897760575`
- Value: `9,067,000` USDC base units
- Note kind: `0x000200000000000000893c499c542cef5e3811e1192ce70d8cc03d5c33590000`
- Deposit address: `0x1F3c1031c7b8b7d9fEECD5CCeDC4f115c2eF952c`

The source-to-deposit transfer and the relayed mint are separated by only 12 seconds and use
the exact same amount.

## Public egress

At 11:09:59, transaction `0x5d03…b99` calls `substituteBurn` on RollupV1:

- [Burn-substitution transaction `0x5d03…b99`](https://etherscan.io/tx/0x5d03d879cd1124a26219ee48d86fdcc9cf155be206f45a1d436c8bf4b38c7b99)
- `burnAddress = 0xc6F4Ad525be064C2ACB28b033231A00BBDdC33ab`
- same note kind as the mint
- `burnHash = 0x18986a83064e3a6a02ff4b1274dfe53d458c75bb054bfe12976f413a0369bb64`
- `amount = 3,060,000` USDC base units
- `burnBlockHeight = 32,791,739`

The challenge destination receives exactly `3.06 USDC`.

## Intended commitment-graph reconstruction

[L2BEAT's Payy assessment](https://l2beat.com/privacy/projects/payy) identifies two relevant
properties of the deployed system:

1. transaction proofs are returned by a public endpoint; and
2. spent and created commitments are public inputs, while the deployed circuit does not use a
   separate nullifier to hide which commitment is consumed.

The [public Payy explorer client types](https://github.com/polybase/payy/blob/main/app/packages/network/src/api.ts)
confirm that every returned proof includes:

```text
input_commitments:  [commitment, commitment]
output_commitments: [commitment, commitment]
messages:           [...]
```

The [UTXO circuit source](https://github.com/polybase/payy/blob/main/noir/utxo/src/main.nr)
defines a burn hash as `commitments[0]`, the first consumed commitment. Consequently, the
complete trace can be reconstructed as follows:

1. Fetch Payy block `32,791,739` and select the burn transaction whose first input is
   `0x18986a…bb64`.
2. For that input commitment, query
   `/elements?elements=<commitment>&include_spent=true` to obtain the transaction that created
   it. The list endpoint is required because the singular endpoint only searches the current
   unspent tree.
3. Fetch that transaction and repeat the process for its nonzero input commitments.
4. Stop when the backward graph reaches the mint transaction whose public `messages[3]` equals
   source mint hash `0x143e78…0575`.

This traversal reveals transaction linkage, not the note secrets themselves. A Payy
transaction can split the `9.067 USDC` mint into the `3.06 USDC` burn note and change, so
equal amounts are not required at every step.

## Current reproducibility limitation

Payy transaction data is kept offchain. The official API base is:

```text
https://validators.mainnet.payy.network/v0
```

On 2026-09-30, `/blocks`, `/transactions`, `/elements`, and `/height` all returned HTTP 502;
the block endpoint still returned 502 when rechecked on 2026-10-01. This followed the
2026-09-24 Payy exploit and network pause. Because the individual transaction proofs are not
posted to Ethereum, the intermediate commitment hashes cannot be independently recovered from
the rollup contract while the operator API is offline.

The report therefore preserves the exact Ethereum boundary transactions, both public Payy
hashes, the burn block height, and the deterministic traversal procedure, but it does **not**
invent or claim an unverified intermediate commitment list.

The API probes and a ready-to-run recovery procedure are recorded in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md#challenge-4--payy).
