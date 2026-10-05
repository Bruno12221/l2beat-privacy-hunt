# Challenge 7 — investigation summary

As of October 5, 2026: **unsolved. No EVM funding source is proven, and no
candidate payment has been linked to the target's private inputs.** We are
closing this investigation pass with reproducible tools and a bounded evidence
record, not announcing an answer. We have not proved the challenge impossible.

## The question and the missing link

The voluntary public challenge asks for the EVM source of the funds that
eventually reached `0x8d5a4fe39f7c4407431e48bd6bf727e5a159f98a` through Zcash.

We verified public funding segments on the entry side and reconstructed the
target's public exit. Zcash hides the connection between them:

```text
possible EVM funder -> swap/bridge -> recovered Zcash payment
                                      [private spend link missing]
                                    -> target Zcash exit -> 0x8d5a…f98a
```

An accurately traced candidate entrance is not automatically the entrance used
by the target. Similar amounts, nearby times and common services do not bridge
that gap by themselves.

## Fixed target facts

| Field | Recorded value |
| --- | --- |
| Zcash exit transaction | `2cfacbf8426140e3e7cc2827d3d410a6dd0749af43d96a1b96a2243e9c56df9c` |
| Mined time / height | September 19, 2026, 10:01:11 UTC / 3,488,707 |
| Anchor height | 3,488,703 |
| Transparent Intents deposit | `t1PdhpgwaocdDreLYVTMHjTjHFneYJJ5Xh9` |
| Private-pool net outflow | 3,954,182 zats = 0.03954182 ZEC |
| Transparent deposit amount | 3,939,182 zats |
| Transaction fee | 15,000 zats |
| Actual Intents swapped input | 3,862,724 zats |
| ETH output | 22,712,389,229,785,027 wei |
| Ironwood actions | Two; compatible with one or two real input notes |

These amounts represent different stages and must not be substituted for one
another. A larger input can leave private change. Earlier private transfers,
consolidation or Orchard-to-Ironwood migration may precede the target's immediate
inputs. The author's full-amount-spent correction referred to **challenge 6**,
not a guaranteed no-change constraint for challenge 7.

## What we accomplished

- Recovered actual payout amounts and receivers where all-zero outgoing viewing
  keys permitted it; kept unreadable outputs and uncollected paths as gaps.
- Built a separate, height-compatible inventory of **12,780 actual positive
  Ironwood outputs**. This is not every output in the private pool and not a
  ledger of unspent balances.
- Searched single-note and two-note budgets. The inventory has **7,372 sufficient
  singles**, **four exact-sum pairs**, and **222,113 pairs** within a chosen
  100,000-zat change window. Exact sums are candidates, not solutions;
  the chosen change window does not exclude larger change.
- Accounted for **18,808 connector requests**: **18,292 distinct explicit pending
  IDs** and **516 branches with observed failed connector descendants**. A
  pending ID still needs settlement verification; a failed branch does not
  exclude a later retry or the wallet's other activity.
- Recovered 197 missing execution trees, obtaining 174 new pending IDs and
  **47 genuinely new eligible notes** after overlap checks.
- Traced selected payouts to accepted initiating accounts, exact executed
  credits and public funding transactions. Distinguished initiating users,
  token funders, submitters, solvers and withdrawal recipients.
- Investigated public migrations, transparent ancestry and source-wallet
  histories. These supplied constraints but no target private-spend link.
- Completed a corrected outgoing Explorer collection: **247 pages / 126,954
  records**, spanning the requested August 2025–September 2026 interval in its
  selected nonpending ZEC-origin scope. Its final offline comparison is recorded
  in the [evidence register](docs/challenge7/EVIDENCE.md).

## Wallet leads: verified segments, unproven target attribution

There is **no defensible highest-probability wallet overall**. Confidence below
means confidence in being challenge 7's source, not confidence that the listed
transaction happened. Percentages would imply a calibration we do not have.

| Wallet | Public evidence / hypothesis | Confidence for #7 |
| --- | --- | --- |
| `0xd9e5df6acc9815121d3e99b49f26e712eb4fe41d` | Verified Base funding segment; route creates a 4,000,000-zat note about 46 hours before the target. Enough value with possible change. | Low; a direct-entry lead only. No independent L2BEAT association or target consumption link. |
| `0x9bf1516fef684393b5722c75539514df42914c5d` | Verified 2-USDC Base deposit funding a 143,950-zat note in an exact-sum pair. | Very low; common control and target consumption are unproven. |
| `0x144813474ffbcecf1eef5251101fde840cfaac36` | Verified 20-USDC Base deposit funding a 2,082,436-zat note in another exact-sum pair. | Very low; common control and target consumption are unproven. |
| `0xebe931092eaee63785d06d862d45af685a83c602` | Twenty verified stablecoin deposits into an investigated Intents account. | Weak/unproven; account funding is established, allocation to the target is not. |
| `0x3124558d1c2c639162cb6129c6ba3ee81d7c669f` | Verified Arbitrum funding on an older public branch entering Zcash. | Weak/unproven; the private continuation to #7 is missing. |

Other amount-only combinations exist, including the remaining exact pairs;
this table is an investigation shortlist, not a complete probability ranking.
The author-disclosed `0x09fbb3e9114e6b5a938f591c8bf75203d8075507` was a public
comparison seed, not a newly discovered funding source. No unrelated wallet
holder's real-world identity is asserted.

## Important corrections and negative results

1. **Recovered outputs are not public spent-note links.** Zero-OVK recovery
   exposes some created notes; it does not reveal which note a later nullifier
   consumed, who controlled it, or whether it remained available.
2. **Public pool value balances are not individual note values.** Migration
   budgets and hidden multi-output payments must not be inserted as plaintext
   notes in an exact-sum solver.
3. **Some promising candidates were returned ZEC change**, not EVM-funded ZEC
   purchases. Their upstream Zcash deposits introduce another private boundary.
4. **The shared transfer account was a Confidential Intents treasury.** Funding
   pooled service inventory does not identify the private customer allocation.
5. **The old outgoing cutoff excluded our own target.** Explorer's record was
   created 3.111 seconds after the quote timestamp. The corrected collection
   recovers and exactly binds the known target route. This delay is observed
   for this record, not a universal rule.
6. **Refund reporting and hash-array roles required care.** Eight public controls
   show reported refund amounts differing from decoded output values. Returned
   Zcash transactions can appear in origin or destination hash lists. We used
   actual note values, not an API amount substituted for them.
7. **Association checks did not corroborate the d9e5 wallet.** Six completed
   candidate Ethereum/Base feeds contained 5,413 events. No direct contact with
   the declared seeds or uncommon shared positive-value peer was found in the
   collected scope; one seed feed remained unresolved. This is not an ownership
   exclusion or a complete organization-wide wallet graph.
8. Earlier rejected Arc/Monad guesses and service/name-based associations are
   not revived as answers. A failed hypothesis is not improved by repeating it.

## What remains unknown

The target may use a directly recovered payment, private change, an intermediate
private transfer, consolidated funds, an older migration or a non-Intents entry.
Diversified receivers belonging to one wallet cannot generally be linked just
by comparing their address bytes. Masking routes, opaque historical payouts,
unobserved private activity and indexer omissions remain outside completeness
claims made here.

The most valuable new evidence would connect the target to a particular
candidate independently of an amount match: an exact user-specific allocation,
meaningful receiver/account reuse, a voluntarily released viewing key or an
author-confirmed transaction. Operator cooperation would require separate
permission; no private logs or access to someone else's wallet were obtained.

**Conclusion:** this pass improves public-edge reconstruction and documents why
the attractive shortcuts failed. It does not solve #7 or demonstrate that no
public solution exists. Further work should begin with new discriminating
evidence, not a more confident amount-only address guess.

## Publication and reproducibility

- [Evidence register](docs/challenge7/EVIDENCE.md): exact public transaction
  identifiers, frozen counts and integrity hashes.
- [Methods and tools](docs/challenge7/METHODS.md): research themes, selected
  scripts, dependencies, tests and replay limitations.
- [Publication handoff](docs/challenge7/PUBLICATION.md): explicit file allowlist,
  package checks and approval boundary.

Selected bulky HTTP responses, account-history caches, transaction records and
ledger exports are available as separate [data release assets](docs/challenge7/DATA.md).
The Git package contains reports, source code, tests and a compact evidence
register. Credentials, binaries, logs, duplicate snapshots and the working diary
remain local. The user approved PR creation and data publication; merging is a
separate decision.
