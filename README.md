# L2BEAT Privacy Hunt investigation

Private working repository for the L2BEAT privacy treasure hunt.

## Result

- Common Ethereum source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://arbiscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Onchain name: `l2beet.gwei`
- Treasure: <https://l2beet.gwei.domains/>

## Current focus

Challenge 6 is traced through Arbitrum, NEAR Confidential Intents, the NEAR–Zcash connector, the Zcash shielded pool, and back through NEAR Intents to its Arbitrum destination.

The important new result is not discovery of the treasure domain. It is reconstruction of the challenge-6 route and direct recovery of the bridge-created shielded Zcash output using the connector's hardcoded all-zero outgoing viewing key.

See [CHALLENGE-6.md](CHALLENGE-6.md) for the trace and [`decoder/`](decoder/) for the reproduction code.

## Status and evidentiary boundary

Public data proves both edges of the Zcash shielded pool and the full route on either side. The connection *inside* the shielded pool is intentionally hidden. Linking the later exit to the earlier payout is therefore an edge-correlation inference, not a public Zcash spend graph.


