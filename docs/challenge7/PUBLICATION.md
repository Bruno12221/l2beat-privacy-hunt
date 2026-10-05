# Challenge 7 — publication handoff

Prepared October 5, 2026. The user explicitly approved creation of the PR and
publication of the investigation data. **This is not approval to merge.**
The package checker itself never stages, commits, pushes or opens a PR.

## Included

The exact selection is [PUBLISH-FILES.txt](PUBLISH-FILES.txt): the updated README,
challenge-6 correction, current challenge-7 summary, compact evidence register,
methods, Rust source/dependencies, useful Python tools with their import closure,
selected tests and the package checker itself. The selected source is an
overlay for this existing repository, not a second independent repository.

The challenge-6 correction is included because the earlier merge interpretation
was explicitly disputed by the author; it is not silently reused as a premise
for challenge 7. This does not claim its remaining private link is proven.

## Data published separately; exclusions preserved locally

The user subsequently requested publication of the data as well. Current data
and supporting evidence are packaged as separately downloadable GitHub Release
assets, with original/published hashes and a directory-level manifest. See the
[dataset guide](DATA.md) for the exact selection and sanitization policy.
Large archives do not enter the Git commit or the source overlay.

Still excluded from publication:

- JWTs, environment files, authentication headers, binaries, compiled Rust
  output, logs and generated package folders.
- The working SQLite database, duplicate checkpoint snapshots and superseded
  data runs. Selected response bodies, exported tables and source histories
  are included in the release assets instead.
- The chronological working diary, obsolete plans/rankings, rejected-address
  explorations, Dune query drafts and the large intermediate reports.

No investigation evidence was deleted. The previous long challenge-7 page was
preserved locally as `CHALLENGE-7-WORKING-HISTORY.md`; the new public page is
the current conclusion, not an accumulation of contradictory "latest" updates.

## Review and package check

```sh
python3 -B scripts/prepare_challenge7_publication.py --test
git diff --check
```

The checker validates the explicit text-only allowlist, local Python import
closure, documentation links and size limits, and rejects common credential
patterns and machine-specific personal paths. This is **not** a universal
secret-detection guarantee; human review remains necessary. The tests run on
only the exported selected files with outbound connections disabled, so absent
local dependencies cannot be hidden by the rest of the working directory.

A fresh ignored folder is generated under `publication-build/`, with the exact
selected overlay and `PACKAGE-SHA256SUMS.txt`. It does not stage files or mutate
the repository's Git history. Existing original investigation data are not copied.

After approval, review and stage only the allowlisted files—**never `git add .`**.
Inspect the staged name list, diff and credential scan before committing.
Any source/doc change after export requires rerunning the package check.
Do not stage generated package folders. Release asset publication is a separate
explicit step after the archive readback and credential-pattern checks pass.

## Suggested future PR

Title: `Document unresolved Challenge 7 investigation and reproducible tools`

Body:

- Record the exact target exit and explicitly missing private-spend link.
- Summarize 12,780 recovered eligible Ironwood outputs, the candidate funders
  and the absence of calibrated attribution probabilities.
- Record the completed 126,954-row outgoing indexer scope and passing known-target
  control; no non-target exact refund-receiver reuse was found in that scope.
- Account for 18,808 selected connector requests, including 516 failed branches.
- Preserve funding-direction corrections, service-treasury boundaries and
  limitations of amount/timing correlation.
- Include selected tools/tests and link separately packaged data release assets;
  keep credentials, binaries, logs and duplicate runs local.

This is a documentation/tooling contribution, **not a solved challenge claim**.
The user approved PR creation and data publication on October 5, 2026. Do not
merge the PR without a separate request.
