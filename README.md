# L2BEAT Privacy Hunt investigation

This repository documents a public-data reconstruction of all six routes in the
[L2BEAT Privacy Hunt](https://privacyhunt.gwei.domains/) and an unresolved
investigation of the legendary Challenge 7.

## Result

- Common EVM source address: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://etherscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Onchain name: `l2beet.gwei`
- Treasure: <https://l2beet.gwei.domains/>

## Challenge index

| # | Privacy system | Destination | Result | Report |
|---|---|---|---|---|
| 1 | Cloaked / Relay | `0x72cc4839fB181fe25e1F1eA8aDa1c497a7C07e7C` | Direct API join | [Challenge 1](CHALLENGE-1.md) |
| 2 | STRK-20 | `0x1718AE64902cfF7601344D7f5801F36c402BDbb0` | One-member anonymity set, followed to Starkgate | [Challenge 2](CHALLENGE-2.md) |
| 3 | Zama confidential ERC-20 | `0x906ff67514449638DadDC09b007f0b7b3023EF33` | Recipient is public in calldata and event topics | [Challenge 3](CHALLENGE-3.md) |
| 4 | Payy | `0xc6F4Ad525be064C2ACB28b033231A00BBDdC33ab` | Exact public boundaries; intermediate API record unavailable | [Challenge 4](CHALLENGE-4.md) |
| 5 | Privacy Boost | `0x64046b48B802d117953b112B1e77AA9aEBA5aA81` | Sparse-set amount/timing correlation | [Challenge 5](CHALLENGE-5.md) |
| 6 | NEAR Confidential Intents / Zcash | `0xF1cDD601C5Edb7F5f5cAFffFF16d1083fee1Ac68` | Full public-edge trace plus zero-OVK recovery | [Challenge 6](CHALLENGE-6.md) |
| 7 | Zcash source investigation | `0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A` | Unsolved; no proven source or private spend link | [Challenge 7](CHALLENGE-7.md) |

All timestamps in the reports are UTC.

## Evidence standard

The reports distinguish three kinds of links:

1. **Direct:** a public transaction, event, calldata field, or protocol API names both sides.
2. **Deterministic reconstruction:** public records leave one candidate in the relevant set.
3. **Inference:** timing and distinctive amounts strongly correlate two otherwise private edges.

This distinction matters for challenges 4–6. Payy keeps transaction data offchain and its
validator API is currently unavailable, so challenge 4's Ethereum ingress and egress are
proven but the intermediate commitment list is not reproduced here. Privacy Boost's challenge
5 link is a small-anonymity-set inference. In challenge 6, the Zcash payout is directly
recoverable, but the later shielded-pool exit cannot be cryptographically tied to that payout.

## Reproduction material

- [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) contains public API and RPC queries for challenges
  1–5.
- [`decoder/`](decoder/) contains the Rust utilities that reproduce challenge 6's all-zero
  outgoing-viewing-key recovery and challenge 7's Ironwood anchor reconstruction.
- [Challenge 7 methods](docs/challenge7/METHODS.md) describes the selected collectors,
  note decoder, candidate checks, offline audits and tests. Historical
  migration budgets are kept separate from actual recovered note values.
- [Challenge 7 evidence register](docs/challenge7/EVIDENCE.md) preserves the important
  identifiers and findings without publishing large caches or credentials.
- [Challenge 7 data downloads](docs/challenge7/DATA.md) links the separately
  packaged evidence archives, file inventory and checksums. Credentials and
  duplicate working snapshots are excluded.
- Every report includes exact transaction hashes, addresses, amounts, timestamps, and the
  privacy failure being demonstrated.

No private wallet material or privileged dataset was used. Some Challenge 7
Explorer reads required an authorized partner token supplied locally; no token
or authenticated response-header material is published. Full local evidence
replays require the deliberately excluded caches and are not advertised as
working from a fresh clone without additional data. Selected evidence is
published as GitHub Release downloads rather than large Git objects.
