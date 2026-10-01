# Challenge 3 — Zama confidential ERC-20

## Answer

- Challenge destination: [`0x906ff67514449638DadDC09b007f0b7b3023EF33`](https://etherscan.io/address/0x906ff67514449638DadDC09b007f0b7b3023EF33)
- Common source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://etherscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Route: USDC → confidential USDC → direct confidential transfer
- Evidence class: direct calldata and event-topic link

## Trace

At 2026-09-19 10:42:11, the source wraps `9.126212 USDC` through proxy
`0xe978F22157048E5DB8E5d07971376e86671672B2`:

- [Wrap transaction `0xbec8…5a2`](https://etherscan.io/tx/0xbec8524b8871b53d3a47671b45afbd9f2fe439a02170a1f01ba766ac3295c5a2)
- Decoded call: `wrap(source, 9126212)`
- Implementation: `0x2ABad2203Eba104b52cf040cCcFA100Df15687F8`

At 10:58:59, the source calls:

```solidity
confidentialTransfer(
    address to,
    bytes32 encryptedAmount,
    bytes inputProof
)
```

- [Transfer transaction `0x8755…857`](https://etherscan.io/tx/0x87555b02e16056c76a02267c8f247c1972fbd71adbcef8a0239cd92387f13857)
- `to = 0x906ff67514449638DadDC09b007f0b7b3023EF33`
- `encryptedAmount = 0xee88e1e887358891d2367ad11453aea880ce84b7010000000000000000010500`

The emitted `ConfidentialTransfer` event also indexes the source and destination in topics 1
and 2. The ciphertext hides the amount, but the transfer graph remains public in two separate
places: calldata and logs.

## Why privacy failed

The confidential token encrypts values and balances rather than counterparties. This is an
important but narrower privacy property: observers cannot read the transferred amount, yet
they can still see exactly who transferred to whom.

[L2BEAT's Zama confidential-token assessment](https://l2beat.com/privacy/projects/zama-confidential-tokens)
describes this metadata boundary. For this challenge, reading the first function argument or
the indexed event topic reveals the answer directly; no timing or amount correlation is
required.
