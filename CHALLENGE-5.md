# Challenge 5 — Privacy Boost

## Answer

- Challenge destination: [`0x64046b48B802d117953b112B1e77AA9aEBA5aA81`](https://arbiscan.io/address/0x64046b48B802d117953b112B1e77AA9aEBA5aA81)
- Common source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://arbiscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Route: Arbitrum USDC → Privacy Boost pool → relayed Arbitrum USDC withdrawal
- Evidence class: sparse-set amount and timing correlation

## Deployment

The route uses Privacy Boost's Arbitrum deployment:

- Entrypoint proxy: [`0x44192215FEd782896BE2CE24E0Bfbf0BF825d15E`](https://arbiscan.io/address/0x44192215FEd782896BE2CE24E0Bfbf0BF825d15E)
- Entrypoint implementation: `0x1CAbFda9A9C14D16302dd7c8F4b6E2A57Aa7b364`
- USDC `PrivacyPoolComplex`: `0x3706e38af05bf0158BCdbB46239f8289980b093f`

## Deposit

At 2026-09-19 11:24:18, the source calls:

```text
deposit(USDC, 12557849, precommitment)
```

- [Deposit transaction `0x5534…5b8`](https://arbiscan.io/tx/0x55340a3d82312b660b0ba0e56461ec96b94ff2de939bf16a2e52ee5c6d4105b8)
- User amount: `12,557,849` USDC base units
- Pool amount after the 0.5% vetting fee: `12,495,060` base units, or `12.495060 USDC`
- Commitment: `0x08a581c7623d081dae891ec1d19d79fa8a4a46d3581635a03c392e6b50ef978d`

The public `Deposited` event indexes the depositor and pool, then emits the commitment and
amount. Its topic is
`0xf5681f9d0db1b911ac18ee83d515a1cf1051853a9eae418316a2fdf7dea427c5`.

## Withdrawal

At 2026-09-20 15:02:48, relayer
`0xCcec679569E3c1E531e27F9561485f21f4B01eD1` calls `relay`:

- [Withdrawal transaction `0x8c47…53a`](https://arbiscan.io/tx/0x8c4776c0fe8a3ade03b5abd0c323e2f45d63dc02e5bb8564e1636fa7994e753a)
- Gross withdrawal: `9,370,000` base units, or `9.37 USDC`
- Net payment to the challenge destination: `9,327,835` units, or `9.327835 USDC`
- Relayer fee: `42,165` units, exactly 45 basis points of the gross withdrawal

The public withdrawal bytes embed the challenge destination and relayer. The proof public
signals include the gross amount. The `WithdrawalRelayed` event indexes relayer, destination,
and USDC, and emits the amount and fee. Its topic is
`0xe9b67844a7bb6e6ac95e8a0de02e4448dbb0c9460be9194348e4bbac6d13c2cf`.

## Anonymity-set analysis

A complete pre-withdrawal event query returned 430 deposits and 531 withdrawals across the
entrypoint deployment. Filtering to the USDC pool/token returned 221 deposits and 287
withdrawals, so the protocol's lifetime set is not trivially small.

The relevant local window is sparse, however:

1. The preceding USDC-pool deposit was `100 USDC` on September 14.
2. The source deposited `12.495060 USDC` on September 19.
3. The only subsequent deposit before the target withdrawal was `600 USDC`, also on September
   19.
4. There was no USDC withdrawal after the earlier September event and before the target's
   `9.37 USDC` withdrawal on September 20.

The `600 USDC` deposit is not a plausible value match. The source's `12.495060 USDC` deposit
is the only contemporaneous, same-order-of-magnitude candidate for the distinctive `9.37 USDC`
withdrawal. The difference is consistent with a private partial withdrawal or change rather
than an exact-denomination mixer.

## What is proven and what is inferred

Proven directly onchain:

- the source's deposit, asset, pool, amount, time, and commitment;
- the destination's withdrawal, asset, gross and net amounts, relayer, fee, and time; and
- the absence of another plausible deposit in the local event window.

Inferred:

- that this particular deposit funded this particular withdrawal. The ZK proof does not expose
  a public deposit-to-withdrawal edge.

[L2BEAT's Privacy Boost assessment](https://l2beat.com/privacy/projects/privacy-boost) also
notes that the TEE operator can observe the transaction flow directly. An external observer
does not need that privileged view for the strong correlation here, but the public evidence
should still be described as an inference rather than a cryptographic link.

The Blockscout event queries and decoding instructions are recorded in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md#challenge-5--privacy-boost).
