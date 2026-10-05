# Challenge 7 — compact evidence register

October 5, 2026. This register accompanies the [investigation summary](../../CHALLENGE-7.md).
It publishes important identifiers and bounded results, not full raw caches.
Hashes below establish local artifact integrity, **not** independent correctness,
consensus validity, private ownership or target consumption. All times are UTC.

## Target public exit

- Zcash: [`2cfacbf8426140e3e7cc2827d3d410a6dd0749af43d96a1b96a2243e9c56df9c`](https://cipherscan.app/tx/2cfacbf8426140e3e7cc2827d3d410a6dd0749af43d96a1b96a2243e9c56df9c).
- Transparent Intents deposit: `t1PdhpgwaocdDreLYVTMHjTjHFneYJJ5Xh9`.
- EVM settlement: [`0xe60c296951cd480d75f0b88d7f2b88cc98ada01cd913dc667f89405aaa419ed0`](https://etherscan.io/tx/0xe60c296951cd480d75f0b88d7f2b88cc98ada01cd913dc667f89405aaa419ed0).
- NEAR roots: `Cf5EK98oNCBRzkLLhGUznw7e8KQnQk3vp6ystnshR6Vx` and
  `92pwF6GDgXzhXNZLEGXcu5wraBaV3y99mpsAHNrLEV7d`.
- Quote clock: September 19, 2026, 10:00:02.472. Explorer creation:
  10:00:05.583. Mined Zcash exit: 10:01:11.
- The final bulk positive control exactly binds the saved target's deposit,
  destination, refund receiver, amounts and transaction hash sets. Recovering
  this known route is not a new source discovery.

## Selected candidate funding segments

### Direct-entry lead, not an answer

`0xd9e5df6acc9815121d3e99b49f26e712eb4fe41d` sends
23,349,549,848,445,170 wei on Base to
`0x369939c868891ee613294ed3574afadd11a917de`, September 17, 12:13:53:

[`0xfd6e5c8d016ab9504af92a7acd9ecb473373443a7b0f7c6e50a3c4ebd6422498`](https://basescan.org/tx/0xfd6e5c8d016ab9504af92a7acd9ecb473373443a7b0f7c6e50a3c4ebd6422498).

Its route produces a recovered 4,000,000-zat Ironwood note at 12:15:15,
height 3,486,532, action 0:

`79277f88d88aae253baa872172a7097dbe8681a263915ec71ead92cdb84669ed`.

The note could cover 3,954,182 zats and leave 45,818 zats of hidden change.
This arithmetic and approximately 46-hour delay do not identify a target input.
Another 10,044,000-zat note goes to the same decoded receiver earlier that day:
`8f73e5bbf24748fc04a87b7dc87e80f22f0389d391818069ed7d5ae3dea8c98b`.
The receiver differs from the target's refund receiver; neither difference
nor absence of visible affiliation excludes a deliberately separated wallet.

### Two exact-pair partners with verified Base funding

USDC token: `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`, chain ID 8453.
The NEAR bridge memo identifies the external transaction before the RPC checks;
these were not global searches for similarly sized token transfers.

| Token-transfer sender | Deposit transaction | Raw USDC amount / log index | Recovered ZEC note |
| --- | --- | --- | --- |
| `0x9bf1516fef684393b5722c75539514df42914c5d` | `0x8d5ba874406521e55ca200ae4d12a5fb45b0ae7d7d8a780134c8d848abe1f37f` | 2,000,000 / 453 | `2e1eaf80e033fa644aba3822ed6c45c04bc9646aad61effaac30b0e44c76d3d8`: 143,950 zats |
| `0x144813474ffbcecf1eef5251101fde840cfaac36` | `0x00f4d48d121f5ae5e710ecea62b4460d016cbc5714953dbcb8b329f37cd8098f` | 20,000,000 / 29 | `0ca9b3567a816967eeb7e9a06533cc0528f0ce9599e61bc754d177533f1e8bd4`: 2,082,436 zats |

Deposit block times are September 10, 14:53:11 and September 3, 16:54:03.
The second transaction's submitter is **not** its token-transfer sender.

Their amount-pair partners are returned change from much larger ZEC deposits:

| Partner note | Value | Earlier Zcash deposit outpoint / gross amount |
| --- | ---: | --- |
| `614b4aa5c8ee19aab30ff680dd68117d2c46c54ead87be7b763b05ad8bf2a022` | 3,810,232 zats | `b761ec4c83163486f9b0c0a05bb2d2b3cd70cf2cd55b784d2c45d57653a79c0c:0` / 202,853,640 zats |
| `f516705f26b20d02b9a0c713f16221854e55efdb200cdbc8f3c54b9dd41ec1ef` | 1,871,746 zats | `07c4377b05ceead2a20f0a6a273acf28b14285153ba1f039c7d7d349226460db:0` / 79,995,911 zats |

Both pairs sum to 3,954,182 zats. Their accounts, keys and receivers are distinct;
common control and target consumption are unproven. The upstream change deposits
themselves have private inputs. No full Merkle-proof or consensus verification
is claimed by the saved indexed metadata checks.

### Other public branches

Twenty RPC-checked stablecoin deposits from
`0xebe931092eaee63785d06d862d45af685a83c602` fund an investigated Intents
account. A separate older branch has verified Arbitrum funding from
`0x3124558d1c2c639162cb6129c6ba3ee81d7c669f`: transaction
`0x27062a486164c6ae0fa66a1705340d545eeaff6ede7be90792464ffc07dfb0ef`,
July 29, 16:48:56, transfers 3,150,945 raw Arbitrum USDC units. The executed
NEAR deposit memo binds chain 42161 and that exact hash to account
`4976d0532475216e3f7e3f0210f133ab6e23377fde736761faf17e00c558dd8a`.
Neither branch supplies allocation through the private pool to the target.
These remain branch-funding facts, not candidate ownership probabilities.

Three investigated note credits reach the treasury account published in
[NEAR's Confidential Intents configuration](https://docs.near-intents.org/integration/market-makers/confidential-example):
`51e8f94d77b5e90dc9852ca6113771e11e8382ce69473a75e313e41665de7cbe`.
Opaque customer allocation and pooled existing inventory prevent substituting
a treasury depositor for the original user.

## Completed outgoing Explorer scope

Requested scope: August 21, 2025 through September 19, 2026, 10:01:12;
ZEC origin; statuses FAILED, INCOMPLETE_DEPOSIT, PROCESSING, REFUNDED, SUCCESS;
no amount, destination or referral filter. PENDING_DEPOSIT is deliberately not
in this follow-up scope. The endpoint's chain filtering excludes masking routes.

| Final audited result | Count |
| --- | ---: |
| Accepted pages | 247 |
| Rows / distinct canonical rows / quote identity keys | 126,954 each |
| Unified Address strings decoded | 62,101 |
| Exact target receiver matches | 1: target self-match |
| Other exact target receiver matches | 0 |
| Exact d9e5 working-candidate receiver matches | 0 |
| Baseline-note/quote receiver match occurrences | 1,777 |
| Distinct matched baseline notes | 1,726 |

The exhausted exclusive interval union is
`2025-08-20T23:59:59.999Z` to `2026-09-19T10:01:12.001Z`; tiny overlaps
cover otherwise excluded query boundaries. Terminal checkpoint and manifest
both report completion, with no stop error, and the actual process has ended.
The resumed run used 249 HTTP attempts, including two 5xx window shrinkages.
This verifies completion of the selected indexer scope, not every private action.

## Actual notes and failed connector requests

V5: 12,780 positive pre-anchor Ironwood outputs; 7,372 sufficient singles;
four exact pairs; 222,113 pairs allowing at most 100,000 zats change.
No availability or consumption is established by these counts.

The 197 recovered trees yield 174 new explicit pending IDs. Their raw replay
recovers 123 Ironwood notes and three Orchard notes. All 123 selected Ironwood
transactions have eligible metadata; 76 notes overlap V4, leaving 47 new.
The final outgoing role audit links 31 new notes to post-quote refund-receiver
metadata (20 SUCCESS/origin-list, six SUCCESS/destination-list, five
REFUNDED/origin-list), but none to the target. These are not 31 independently
verified refund controls.

The remaining 516 no-pending-ID branches have observed failed connector
descendants: 493 missing-UTXO errors, 11 expiry-height errors, six Orchard-bundle
errors, three signing-queue errors, two receiver errors and one gas-fee error.
Failed branches do not establish refunds, no retries, wallet exclusions or
whole-chain completeness.

## Local evidence pins

Local artifact names below identify retained evidence, not files included in
the publication. Obtain the corresponding data separately to perform full
cache replays. Never upload whole caches just to satisfy a missing file.

| Artifact | SHA-256 |
| --- | --- |
| V4 `decoded-notes.jsonl` | `f9c7bc70f4013b8733cdfaac3d32d82a29dea8c7384dbd1d7d3c5a78c8cc7aaa` |
| V5 `decoded-notes.jsonl` | `34ad8fa5343def6c330598659e50d93b38a84e2a37f6a5c50aeac121aa41448b` |
| Frozen `note_ledger` binary | `f91b3a2cb0611993dd8415397c88b26b98a4444f8582c7edaa6cc09110e37875` |
| Failed-request `analysis.json` | `b3593b581dd837c05245ae99fb26d4e1581360b3d6bee788cdf1979681531160` |
| Final outgoing `analysis.json` | `124ba9d29801b9fa6d76b686a3057a514bf03b9f90fd21d2d9d448a46ba3192f` |
| Final outgoing audit `manifest.json` | `b1b5e6146592a4ebde05ca1d1e866b033d1274cc35b1082b99b95c5d57367690` |
| Terminal outgoing `checkpoint.json` | `7832e93b2387ace3d47b3a9cba260bfa91ec46af396ea682dab7e42765a5f3bd` |
| Terminal outgoing collection `manifest.json` | `f86682864a50c72385ab52de2c807b5e4b98cd619161974ab1c199a14236e804` |
| Final rescued-note role `analysis.json` | `12471b1426fda89d864c63b34dd5ea7dc98b7bce1a7997fcc2f5784d6c675651` |

The collection's original response envelopes, execution trees, decoded ledgers,
RPC receipts and full hash registries remain local. Binary hashes can vary when
rebuilt; do not replace a pinned historical decoder inside a completed replay.
