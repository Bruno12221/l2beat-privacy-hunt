# Challenge 7 — methods and selected tools

See the [summary](../../CHALLENGE-7.md) and [evidence register](EVIDENCE.md).
This is a bounded public-data investigation, not a claim of full private-pool
coverage or a method for cryptographically linking arbitrary shielded spends.

## Research themes we tested

Our research review used L2BEAT's [privacy best practices](https://l2beat.com/publications/privacy-best-practices)
and [Zcash/NEAR Intents profile](https://l2beat.com/privacy/projects/zcash-near-intents),
along with its other protocol profiles as methodological analogues. The useful
themes were public-boundary correlation, receiver/refund reuse, gas and token
funders, split/merge/change behavior, client/service fingerprints and the
difference between a theoretical anonymity set and an observed eligible set.

The actionable work was:

1. Reconstruct the target's exact amounts, anchor and transaction shape.
2. Enumerate independent connector requests, not only Explorer rows returned
   by a price/date filter. Verify successful descendants and explicit pending
   IDs; do not equate an initial success with a completed callback.
3. Fetch raw serializations and decode actual outputs where zero OVK works.
   Retain opaque outputs and public migration budgets as separate evidence
   classes, never fabricated plaintext note amounts.
4. Apply canonical-metadata/anchor eligibility and stable note identity checks.
5. Search one/two-note budgets, including change. Treat exact sums as hypotheses
   and compare against the large background candidate set.
6. Trace selected candidate public segments through executed credits/mints and
   exact external transactions. Distinguish source funders, submitters, solvers,
   pooled treasuries and destination recipients.
7. Test receiver reuse against a corrected outgoing scope with a known-target
   positive control. Bind original response bytes and exact typed receivers.
8. Seek independent corroboration; preserve negative results and missing scopes.

Viewing keys, operator databases and network/session logs could supply evidence
we do not possess. No such material was obtained or inferred from the chain;
operator cooperation is not assumed and requires separate permission.

## Useful entry points

| Tool | Purpose / limitation |
| --- | --- |
| `decoder/src/bin/note_ledger.rs` | Deterministic raw transaction parsing and zero-OVK output recovery; no private spend proof |
| `decoder/src/bin/unified_receivers.rs` | Exact typed Unified Address receiver decoding; different diversifiers do not exclude one wallet |
| `decoder/src/bin/ironwood_anchor_scan.rs` | Public tree/anchor constraints, not account ownership |
| `scripts/collect_challenge7_outgoing_quotes.py` | Paced immutable-scope Explorer collection; environment-only JWT, bounded calls, fail-stop auth/rate handling and adaptive windows |
| `scripts/analyze_challenge7_outgoing_collection.py` | Original-byte, query-scope, pagination and exact receiver audit; distinguishes live snapshot from terminal completion |
| `scripts/collect_challenge7_raw_batches.py` / `audit_challenge7_batch_notes.py` | Bounded raw batch reads and deterministic decoder replay |
| `scripts/enrich_challenge7_pending_notes.py` | Canonical indexer metadata and pre-anchor eligibility; not consensus verification |
| `scripts/audit_challenge7_connector_ids.py` / `rescue_challenge7_missing_connector_trees.py` | Exact pending-event provenance and missing-root rescue |
| `scripts/merge_challenge7_rescued_notes.py` | Separate V5 note inventory with strict overlap and all new-containing pair counts |
| `scripts/audit_challenge7_failed_requests.py` | Offline failed-descendant classification in the declared request scope |
| `scripts/audit_challenge7_receiver_chronology.py` / `audit_challenge7_rescued_quote_roles.py` | Quote/note chronology and hash-list roles; metadata linkage is not spending |
| `scripts/trace_challenge7_candidate_history.py` / `verify_challenge7_candidate_history.py` | Candidate public histories and selected RPC corroboration |
| `scripts/trace_challenge7_new_receiver_pairs.py` / `verify_challenge7_exact_pair_funding.py` | Selected initiating accounts and exact candidate funding segments |
| `scripts/solve_challenge7_note_budget.py` | Earlier exploratory budget solver; its pool-level migration estimates are not V5 plaintext notes or probability rankings |

The publication allowlist includes their local import dependencies and selected
fixture tests. Helper modules may retain exploratory entry points; their old
rankings are not the current conclusion. No unbounded all-universe shell
orchestrator is included or recommended as a fresh-clone command.

## What can be reproduced from the public package?

The exported source and selected regression tests run without private caches.
Full historical data replays do **not** run from a fresh clone alone. Download
the separate [evidence archives](DATA.md) for the selected raw envelopes,
baseline records and ledger exports. Some scripts deliberately pin old local
snapshot hashes, and manifests sanitized to remove machine paths have separate
original/published hashes. The archives do not make every legacy command turnkey.

From the repository root:

```sh
# Validate the explicit file selection. No Git index changes or network writes.
python3 -B scripts/prepare_challenge7_publication.py

# Export only those files and run their tests with outbound connections disabled.
python3 -B scripts/prepare_challenge7_publication.py --test

# Build Rust in a separate directory; preserve the historical decoder binary.
CARGO_TARGET_DIR=publication-build/decoder cargo build --locked --manifest-path decoder/Cargo.toml --bins
```

Raw fetches are opt-in and paced. Explorer access may require a locally supplied
authorized `NEAR_INTENTS_JWT`; never place it in source, CLI arguments, logs,
commits or published evidence. Free public NEAR/raw/RPC sources replaced the
need for a paid Dune subscription, but do not eliminate indexer completeness
and historical availability limits.

Fixture tests cover pagination, immutable scopes, source hashes, exact identities,
amount/role distinctions and failure handling. They do not prove the challenge
solved. Some fixtures intentionally print simulated timeout or 429 messages;
these are not live network failures.
