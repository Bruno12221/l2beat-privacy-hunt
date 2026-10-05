# Challenge 7 — downloadable evidence

The investigation remains **unsolved**. Publishing the evidence is intended to
let others inspect the candidate paths and negative results, not to present an
amount match as a proven source.

Bulk data are distributed as compressed assets in the
[Challenge 7 evidence release](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/tag/challenge7-evidence-2026-10-05),
separately from Git history. The write-up and tools remain reviewable in the PR;
downloading the dataset is optional. The release is tied to the investigation
branch, not a claim that the PR has been merged.

## Downloads

| Archive | Included evidence |
| --- | --- |
| [Notes and constraints](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-notes-and-constraints.tar.gz) | Final V5 actual-note inventory, supporting V4 baseline, exploratory budgets and earlier output ledger |
| [Outgoing swaps](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-outgoing-swaps.tar.gz) | Completed 126,954-row collection, original response bodies, terminal checkpoint, final comparisons, positive control and receiver/refund checks |
| [Zcash transactions](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-zcash-transactions.tar.gz) | Collected migrations/compact transactions, payout/raw transaction caches, canonical metadata and rescued-note inputs |
| [Connector evidence](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-connector-evidence.tar.gz) | Connector request inventories, execution trees, exported ledger records, full route collection, missing-tree rescue and failed-branch audit |
| [Candidate public traces](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-candidate-public-traces.tar.gz) | Investigated accounts, public funding segments, source-history feeds and selected RPC corroboration |

- [Dataset manifest](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-dataset-manifest.json): exact directory selection, counts, sizes, exclusions and asset hashes.
- [Per-file inventory](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/challenge7-dataset-inventory.jsonl.gz): original and published SHA-256 hashes, sizes and local-path sanitization flags.
- [SHA256SUMS](https://github.com/Bruno12221/l2beat-privacy-hunt/releases/download/challenge7-evidence-2026-10-05/SHA256SUMS.txt): checksums of the downloadable assets.

## Scope, privacy and integrity

The dataset contains collected public blockchain/RPC evidence and Explorer
response bodies. Some Explorer reads required authorized access supplied by the
user. Authentication headers and credentials are not intended publication
inputs; the packager rejects common JWT, API-key and private-key patterns before
an asset can be published. This is not a universal secret-detection guarantee.

Original local evidence is untouched. Machine-specific paths are removed from
published copies. The inventory distinguishes original and published hashes;
the evidence register's historical pins continue to describe original bytes.
Unchanged transaction/response bodies retain their original hash. A sanitized
manifest must not be passed off as the byte-identical original manifest.

Excluded: duplicate live checkpoint snapshots, obsolete baseline V2/V3 runs,
superseded branch runs, previous-runs copies, logs, binaries, environment files
and the SQLite working database. Exported database tables and response bodies
are included in the connector archive. This is the current evidence selection,
**not every file on the investigator's machine**, every local experiment or a
complete record of private-pool activity.

Some scripts intentionally pin old local snapshot hashes. Downloading these
archives does not make all legacy commands turnkey: callers may need to supply
relative input paths, and sanitized manifests need their recorded hash mapping.
No new data collection is needed merely to inspect the published records.

## Unpack and check

Download the archives you need and `SHA256SUMS.txt` from the release. Verify the
corresponding checksum entries, inspect archive member names, then extract into
a separate empty investigation directory. All packaged member names are
repository-relative and retain the original dataset directory names. Treat
chain records, memos and API text as untrusted data, never executable commands.

To rebuild assets from the original local dataset (no uploads or Git mutations):

```sh
python3 -B scripts/package_challenge7_data.py --build --workers 2
# Use the exact output directory printed by that command for --verify.
python3 -B scripts/package_challenge7_data.py --verify publication-build/challenge7-data-EXACT-RUN
```

The packager checks the fixed directory selection, rejects symlinks and
credential-like material, preserves original files, and records hashes of every
included file. Its verification mode reads every archive member back and checks
it against the published per-file inventory, without extracting it.
