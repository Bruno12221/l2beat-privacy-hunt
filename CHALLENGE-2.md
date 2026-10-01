# Challenge 2 — STRK-20

## Answer

- Challenge destination: [`0x1718AE64902cfF7601344D7f5801F36c402BDbb0`](https://etherscan.io/address/0x1718AE64902cfF7601344D7f5801F36c402BDbb0)
- Common source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://etherscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Route: Ethereum → Layerswap → Starknet → STRK-20 → AVNU → Starkgate → Ethereum
- Evidence class: deterministic reconstruction followed by a direct calldata link

## Ethereum to Starknet

1. At 2026-09-19 12:16:11, the source funds fresh EIP-7702/Ithaca account
   `0x235FEfF8D9bEBd27C091e0B2C184d0b01A4bBA54` with `0.0039 ETH`.
   - [Ethereum transaction `0x444d…381`](https://etherscan.io/tx/0x444d5adf920e2efb60a51be10adb62f7302c8ff3b1c71506534f1144acf77381)
2. The Ithaca account pays `0.003837114006211856 ETH` to fresh Layerswap deposit EOA
   `0x8d03b525a9DF237B88e560cb9EE2eD6347649148`.
   - [Ethereum transaction `0x3942…7b3`](https://etherscan.io/tx/0x3942c6f4e689b70efe5e4e6de81de2eff43fbbaba396325be38414757f0187b3)
3. The deposit EOA forwards `0.003819338110844 ETH` to Layerswap 1.
   - [Ethereum transaction `0x0087…1c`](https://etherscan.io/tx/0x0087eb3d2fabbd71c33f3c996129facd28eb0f20284dffaa51a55ba46705901c)

Layerswap's public explorer API maps that input to swap
`e60817a2-8aaf-4b8c-8ce1-0b076b2467b1`. It names Starknet destination
`0x04254b2436ce0343b4e2662fdfe06754fd3578c6a503a46f45edc26c590daab7`,
an output of `0.00380269 ETH`, and the Starknet settlement transaction:

- [Starknet transaction `0x07ab…3ec`](https://voyager.online/tx/0x07ab2a4a6b8933387c4989af71dce6da552de4ddcf237fd865bd94ddfd3473ec)
- [Layerswap API record](https://api.layerswap.io/api/v2/explorer/0x0087eb3d2fabbd71c33f3c996129facd28eb0f20284dffaa51a55ba46705901c?version=prod&page=1&statuses=Completed&statuses=PendingWithdrawal&statuses=PendingRefund&statuses=Refunded)

## Entry into STRK-20

The Starknet account first swaps ETH to STRK for gas, then STRK to `strkBTC`:

- [ETH → STRK transaction `0x431a…470`](https://voyager.online/tx/0x431ab112a8d788c35d7d28ec6730461a88fb76a4da688cf7745f29c31912470)
- [STRK → strkBTC transaction `0x92bb…492`](https://voyager.online/tx/0x92bb9e5d88dc0067dac4517e8e0385aedea7e1bfc23a694f1bdcdb63eca492)

The second swap pays the account `11,502` units of `strkBTC`. The token contract is
`0x0787150e306e6eae6e3f79dea881770e8bbff2c1b8eb490f969669ee945b3135` and uses eight
decimals.

At 12:51:51, the account deposits `11,500` units (`0.00011500 strkBTC`) into the canonical
STRK-20 pool `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`:

- [Deposit transaction `0x434e…eba`](https://voyager.online/tx/0x434ecba9d2730851f83e7bb0a955c40df2f5081d83b7d875328f1035cc34eba)
- Starknet block `15,115,897`

The pool's public `Deposit` event identifies the depositor, token, and amount. Its selector is
`0x9149d2123147c5f43d258257fef0b7b969db78269369ebcf5ebb9eef8592f2`.

## The one-member anonymity set

Querying this pool's deposit events from blocks `15,100,000` through `15,116,601`, filtered
for the `strkBTC` token, returns exactly one event: the `11,500`-unit deposit above.

At 13:11:34—19 minutes 43 seconds after the deposit—the pool withdraws `10,000` units
(`0.00010000 strkBTC`) to fresh Starknet account
`0x031fb637db1b80152c4231f2a9c99a3c939b660b68da4949dba3e7422a4b7a4c`. The same
transaction withdraws another `398` units as the fee:

- [Withdrawal transaction `0x6352…e49`](https://voyager.online/tx/0x63522eda1a41c57ac3000b5b97d05bb6b68d196d25b0fb0abd577cf697e9e49)
- Starknet block `15,116,601`
- `Withdrawal` selector `0x2eed7e29b3502a726faf503ac4316b7101f3da813654e8df02c13449e03da8`

Because there was only one deposit of this asset in the relevant pool window, the public
asset, amount, and timing reduce the anonymity set to one.

## Starknet back to the Ethereum destination

The withdrawal account later swaps all `10,000 strkBTC` units to ETH through AVNU:

- [AVNU transaction `0x3a1d…61b`](https://voyager.online/tx/0x3a1d8b4d4898a1d9a8241a02a7919a4d1069399b3931f35a3d7bc8f7948061b)

After a gas top-up in [`0x7ec1…8c6`](https://voyager.online/tx/0x7ec1a1f757b3276376e0698a60b90211c3477b603953a496cb15a73a1c008c6),
it calls Starkgate at 16:29:00:

- [Starkgate transaction `0x33a9…615`](https://voyager.online/tx/0x33a9e8e4a752d78ddb9fa79e451a53b31f216547138508abbed100987469615)

The calldata directly contains:

- token identifier `0x455448`, or `ETH`
- amount `0x9d63ece14b6ec`, or `0.002768840024176364 ETH`
- Ethereum recipient `0x1718AE64902cfF7601344D7f5801F36c402BDbb0`

Starkgate later pays that exact amount to the challenge destination:

- [Ethereum transaction `0xff55…f4c`](https://etherscan.io/tx/0xff55ea482fa00b5dec342a0cc8cd4210f624edc97841940a20dba007c5f8cf4c)

## Why privacy failed

[L2BEAT's STRK-20 assessment](https://l2beat.com/privacy/projects/strk20) notes that the
deposit and withdrawal sides expose public metadata. Here the uncommon asset had only one
deposit in the relevant window. Once the fresh withdrawal account is identified, its AVNU swap
and Starkgate call are ordinary public transactions, and Starkgate writes the Ethereum
recipient directly into calldata.

The event query used to establish the one-member set is recorded in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md#challenge-2--strk-20).
