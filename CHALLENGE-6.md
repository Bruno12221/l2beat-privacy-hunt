# Challenge 6 trace

## Answer

- Challenge destination: [`0xF1cDD601C5Edb7F5f5cAFffFF16d1083fee1Ac68`](https://arbiscan.io/address/0xF1cDD601C5Edb7F5f5cAFffFF16d1083fee1Ac68)
- Common source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://arbiscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Treasure: <https://l2beet.gwei.domains/>
- Route: Arbitrum → NEAR Intents → NEAR Confidential Intents → Zcash → NEAR Intents → Arbitrum

All times below are UTC.

## Source to the confidential shard

1. At 2026-09-19 19:47:57, the source sends `0.00073 ETH` on Arbitrum to fresh deposit EOA `0xBc33C41Ed07CCBb2a92bd7842606e48455BFB2f9`.
   - [Arbitrum transaction `0x5465…1a7a`](https://arbiscan.io/tx/0x5465f381989351e9f4a8f345ea6f1599531cd37c53c95123fc218ba123d81a7a)
2. Two seconds later, that EOA sweeps the same amount to the NEAR Intents treasury `0x2CfF890f0378a11913B6129B2E97417a2c302680`.
   - [Arbitrum transaction `0x8383…29af`](https://arbiscan.io/tx/0x8383ea6547b22508091759e105ec1d7096e8cae47aa5083b150d735347e029af)
3. NEAR transaction `J8RgLEgsTxfkZt1R519w5AuMopvKKxmAFZnWyQxV7QA2` publicly mints `730000000000000` units of `arb.omft.near` to Intents ID `ec3e6c29c5cfacd8f407be9d1017c8ad34ae43c8b6ff258b3c8b8935e094b8f5`.
4. The mint memo publishes the original Arbitrum transaction hash, linking the chains directly.
5. At 19:48:06, the credited ID transfers the entire amount to shared confidential bridge account `51e8f94d77b5e90dc9852ca6113771e11e8382ce69473a75e313e41665de7cbe` with an encrypted memo.
   - NEAR transaction `3bBW7om2ohcQAmy7aRF2Kg5Lf4x7M1FV4beRd9yMeSrR`
   - Intent hash `DBhcPFbMwDSpJzzPyKVDP3nmgg3ZY661ZVbZBLRoW4tK`

## Confidential settlement leakage

The private-shard execution is not publicly readable, but its bridge settlements are:

1. At 19:50:48, the shared confidential account sends exactly `729999270000000` units of `arb.omft.near` to `solver-multichain-asset.near`—only 730 wei below the source deposit.
   - NEAR transaction `dcVL2aV8sMAgr2RS9auN3w3N6oTh5kEeXdZGS14kAtE`
   - Intent hash `5jSFU8DfpVhfZmzTcXEU8LUiWijXFgNr8b67BbzYLUoF`
2. At 19:52:57, `solver-priv-liq.near` sends `200496` zats of `zec.omft.near` to the shared confidential account.
   - NEAR transaction `DErVjqiWWkcKZheJN9fN3xWhZMsSKuCsUoqQh85oVwkV`
   - Intent hash `7qPEdcC3SZm37YKj6t25Z7xaCHWxsqc1BB9pVurUZvbY`
3. At 19:54:39, the shared account sends `200490` zats to fresh public Intents ID `10b1b6f28a9ad113f7dbc20cea86c578cacc3eccd7129aa6fc10538644e19467`.
   - NEAR transaction `C4QF8MiCHUzN3tz2V9fawMnrMY2u8nJT9dXNY3yr3SyX`
   - Intent hash `AynT2fgbSf5h1yycbP6xuyH5h2Fph7AfaJQcNhkobVwv`

This exact amount-and-time sequence identifies the source-side confidential swap without reading its encrypted instruction.

## Zcash payout

At 19:54:45, the fresh public ID spends all `200490` zats:

- `168490` zats are requested for withdrawal to unified address `u16pg4dnxy3a20qz4u2dccms6k50psm8s2vcwa5pvuksd2vc9kdzca0u7u2wx785em6jap5y9gn2vyxtc74mnzu2ak4ja6nd0hwxrzthpvnce2re04aef9z05qnjh7649h69atxxkq367ypzm6lqkq8mkn07qwwfqtyeyg4jcrpy9s5gy4`.
- `32000` zats go to Intents ID `5880ad2b362620fadf759cbceb1cd5737ce8c6ed7fb8e9942881e6731f9247dd`.
- NEAR transaction: `DRPUYX1mRxnktWBKtuma8MrzgPEYrc8cMYUryv5WVMmL`
- Intent hash: `5vVJEZqQg9D4gq1NEruDYHqn1qRSz5u97b4LezAsjnDm`

The bridge constructs the Zcash transfer in NEAR transaction `Ai2QD6JGtG4kYsTVn7rnZ7CmdkePBtDBESMVjSoo1pqi`, with origin nonce `505862` and destination nonce `19375`.

The resulting Zcash transaction is [`16c78159ec131f770cc396825a837e90ee7903de3f0aac329df4073598014d94`](https://cipherscan.app/tx/16c78159ec131f770cc396825a837e90ee7903de3f0aac329df4073598014d94), confirmed at 19:59:12 in block 3,489,193. NEAR verifies it in transaction `9jtit41tSbf6doxEwyqpE7PVwHwMCGbTLP7As8t9PvVw`.

The transaction contains:

- Two transparent bridge inputs totaling `13,195,001` zats.
- One transparent change output of `13,036,511` zats.
- One shielded Ironwood action.
- Public Ironwood value balance `-143490`, meaning 143,490 zats entered the shielded pool.
- A 15,000-zat Zcash transaction fee. A further 10,000 zats were deducted between the NEAR withdrawal and Zcash construction.

## The all-zero viewing-key leak

The connector source defines:

```rust
pub const BRIDGE_OVK: [u8; 32] = [0u8; 32];
```

It uses that key to recover the output note and validate its recipient and value. Because the key is public and identical for every bridge payout, any observer can perform the same recovery.

- [Connector implementation](https://github.com/Near-One/btc-bridge/blob/4711c2f1d035a208464b9729bb24e45ed9ab7831/contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs#L14-L96)
- [L2BEAT research](https://l2beat.com/privacy/projects/zcash-near-intents)

Running the decoder in this repository against `16c78159…d94` recovers:

```text
recovered_value_zat=143490
recovered_recipient_raw=25b284936ad32e2eb79ceb524324054ab376a0f85427fb31fca5cb7082f887e0b778da93678f63a4ae5620
target_ua_match=true
```

This is a direct cryptographic recovery of the nominally shielded payout—not a timing guess.

## Return leg to challenge 6

Roughly 33 hours later, Zcash transaction [`7dbb78271a72deab90aed751eb5d8868bdcb4d177cafb65afd5b3d2c17394892`](https://cipherscan.app/tx/7dbb78271a72deab90aed751eb5d8868bdcb4d177cafb65afd5b3d2c17394892) exits the shielded pool:

- It has zero transparent inputs.
- It creates one transparent output of `313096` zats to fresh bridge route `t1Tns7XV5WzdZQqq7ZNHEgufSd7YKyNPg9D`.
- NEAR credits `306651` zats after the bridge fee in transaction `9vg12ikserjUuGJ85tY6mdfaWTi5Qus6nZabvD3xKLUY`.
- The swap executes in NEAR transaction `7KiVgpB7jExqToD1JceQLPUD6H5FBrmjHcqF1Rb7TbCA`, intent hash `J2zps4CsfYfT2xTn2Mm8h5z7JyoGo6bN3Y3QL6Y4zjCw`.
- [The official NEAR Intents explorer](https://explorer.near-intents.org/transactions/t1Tns7XV5WzdZQqq7ZNHEgufSd7YKyNPg9D) identifies the route as `0.00306651 ZEC` to `0.001727998 ETH` on Arbitrum.
- Challenge 6 receives `0.001727998076663010 ETH` in [Arbitrum transaction `0x9c6a…4768`](https://arbiscan.io/tx/0x9c6af9bab0ccd2ef7e2ce6285e85c4d35792ebc7f12ebf727e1435097dfc4768).

## What is proven and what is inferred

Proven from public artifacts:

- The common source funded the exact confidential ingress.
- The corresponding confidential settlement produced the wrapped-ZEC payout.
- The Zcash bridge payout address and amount can be decrypted with the connector's public all-zero OVK.
- A later transaction funded from the shielded pool entered a fresh NEAR Intents route and paid challenge 6.

Inferred:

- That the later shielded-pool exit belongs to the earlier payout. Zcash correctly hides the internal spend graph. The return amount is larger than the recovered payout note, indicating that notes were merged or additional shielded funds were used.

The intended deanonymization is therefore a combination of deterministic public leakage around Confidential Intents and its Zcash connector, followed by the documented Zcash round-trip edge-correlation heuristic.

