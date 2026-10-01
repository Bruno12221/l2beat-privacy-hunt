# Challenge 1 — Cloaked / Relay

## Answer

- Challenge destination: [`0x72cc4839fB181fe25e1F1eA8aDa1c497a7C07e7C`](https://basescan.org/address/0x72cc4839fB181fe25e1F1eA8aDa1c497a7C07e7C)
- Common source: [`0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A`](https://arbiscan.io/address/0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A)
- Route: Arbitrum USDC → Relay → Base USDC
- Evidence class: direct API join

## Trace

Relay assigned the transfer request ID
`0x17898153392c985f330b7fafd7f9dd196ff86acd63b39b07dcbe12b3e1700667`.

At 2026-09-19 10:55:48, the source sent `9.1 USDC` on Arbitrum to Relay's depository
`0x4cD00E387622C35bDDB9b4c962C136462338BC31`:

- [Arbitrum transaction `0x7c89…b49`](https://arbiscan.io/tx/0x7c896680bde6d08898babc9b639529e73e6cab38982cd9f3e971136a2ef19b49)

Three seconds later, Relay settled `9.074557 USDC` on Base to the challenge destination:

- [Base transaction `0x9b21…078`](https://basescan.org/tx/0x9b21ed4311ce76eae3b4cced178b1bfc30220b3adf9a34c3250bb4f8dff89078)

## The identifying leak

Relay's unauthenticated request-history endpoint accepts an address as its `user` parameter:

```text
GET https://api.relay.link/requests/v2?user=0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A
```

Its response directly contains all of the following in the same request object:

- `user = 0x8d5A…f98A`
- `recipient = 0x72cc…7C7C`
- the Arbitrum input transaction
- the Base output transaction
- input and output amounts
- both chain IDs and timestamps

The independent status route returns the same source and destination transactions:

```text
GET https://api.relay.link/intents/status/v3?requestId=0x17898153392c985f330b7fafd7f9dd196ff86acd63b39b07dcbe12b3e1700667
```

## Why privacy failed

[L2BEAT's Cloaked assessment](https://l2beat.com/privacy/projects/cloaked) describes a wallet
layer that uses fresh recipient addresses. A fresh EOA can hide ordinary address reuse, but it
does not help when the routing service retains and publicly returns the original user and the
fresh recipient in one record. No amount or timing heuristic is needed for this challenge.

## Verification

The exact API commands and expected fields are recorded in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md#challenge-1--relay).
