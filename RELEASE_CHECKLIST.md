# Release checklist — unicode_security 0.1.0

Move through the five states in order. Each external transition needs explicit
maintainer authorization; a passing gate does not authorize the next transition.
Milestone 5C ends at the local candidate. Keep `CHANGELOG.md` at
`## [0.1.0] - Unreleased` throughout local hardening.

## 1. Local candidate

- [ ] Commit the implementation and verify `git status --short` is empty.
- [ ] Fetch development dependencies with `mix deps.get` before qualification.
- [ ] Record `git rev-parse HEAD` and run the complete gate from that clean commit:

  ```text
  mix rc --report /absolute/evidence/local-<commit>/release-candidate.term
  ```

- [ ] Retain the report outside the tracked checkout. Decode it with
  `:erlang.binary_to_term(File.read!(path))` in Elixir and confirm `status: :passed`,
  version `0.1.0`, the exact source commit, all stage results, the five property
  seeds, archive byte size and SHA-256, and empty before/after repository status.
- [ ] Verify `git status --short` remains empty. Any failure creates a new
  candidate after a fix; rerun the entire gate without waivers or skipped stages.

## 2. Hosted candidate

- [ ] Obtain separate authorization to push the local candidate, then run
  `git push origin main` (use the approved release branch if different).
- [ ] Obtain separate authorization for hosted workflow execution. In GitHub's
  Actions page choose **CI**, **Run workflow** (`workflow_dispatch`), and the
  approved branch. No dispatch inputs or publication credentials are required.
- [ ] Verify the run's source SHA equals the local report commit and the pushed
  branch SHA. Wait for every Linux, macOS, and Windows `test` matrix job and the
  dependent `release_candidate` job to pass. The latter runs
  `mix rc --report tmp/release-candidate.term` on Ubuntu / Elixir 1.20 / OTP 29.
- [ ] Retain the run URL, source SHA, complete downloadable workflow logs, and
  local term report together. A skipped or failed RC job is not hosted evidence.

The workflow has `contents: read` and cannot publish. Hosted failure blocks
finalization, tagging, and publication; a fix repeats both local and hosted gates.

## 3. Finalized candidate

- [ ] Obtain separate authorization for release finalization. Confirm the intended
  publication date, then replace the 0.1.0 changelog's `Unreleased` value with that
  actual date. Do this only when ready to publish; if the publication day changes,
  correct the date and repeat finalization and both gates.
- [ ] Commit the dated changelog with
  `git add CHANGELOG.md` and `git commit -m "docs: finalize 0.1.0 release notes"`.
- [ ] Run `git rev-parse HEAD`, verify a clean checkout, and rerun
  `mix rc --report /absolute/evidence/finalized-<commit>/release-candidate.term`.
- [ ] Obtain authorization to push this finalization commit and dispatch the
  manual hosted workflow again. Repeat every hosted verification for this exact
  commit, retaining the new report and run logs. Earlier green commits are not
  evidence for the finalization commit.

## 4. Tagged release

- [ ] Obtain separate authorization to create an annotated release tag. Confirm
  `git status --short` is empty and `git rev-parse HEAD` equals both the final local
  report commit and the green hosted run SHA.
- [ ] Create the tag with `git tag -a v0.1.0 -m "unicode_security 0.1.0"`.
- [ ] Confirm `git rev-parse v0.1.0^{commit}` equals `git rev-parse HEAD` and both
  gate commits. A tag on any other commit must not be published.
- [ ] Obtain separate authorization to push the tag, then run
  `git push origin v0.1.0`. Record the tag object and peeled commit identity.

## 5. Published release

- [ ] Before publication, perform a fresh public Hex package-name check:

  ```text
  curl --silent --show-error --output /absolute/evidence/hex-name.json --write-out '%{http_code}\n' https://hex.pm/api/packages/unicode_security
  ```

  The Hex API returned **404 for `unicode_security` on 2026-10-07**. This is a
  point-in-time observation, not a reservation. A fresh 404 supports availability;
  a 200 requires verification of ownership and existing versions. Other statuses
  or network errors do not prove availability and must be resolved before release.
- [ ] Confirm the project still reports version `0.1.0`, the changelog date is the
  actual publication date, and `git rev-parse HEAD` and
  `git rev-parse v0.1.0^{commit}` still match both passing gates.
- [ ] Review `mix help hex.publish` for current Hex publication and rollback rules.
  Obtain separate authorization for Hex publication. Authenticate locally with an
  approved maintainer account; CI must never receive publication credentials.
- [ ] From that clean tagged source run `mix hex.publish` and review its package
  and documentation confirmation prompts. The RC gate's
  `mix hex.publish --dry-run` only performs local checks and does not publish.
- [ ] Verify the public Hex API and package page show 0.1.0, download the published
  archive, and compare its SHA-256 with the finalized RC archive. Verify the
  versioned HexDocs site. In a new production consumer use
  `{:unicode_security, "== 0.1.0"}`, run `MIX_ENV=prod mix deps.get` and
  `MIX_ENV=prod mix compile --warnings-as-errors`, then exercise the same public
  identifier, skeleton, comparison, domain, conflict, and batch checks as the RC
  consumer. Retain downloaded-package and consumer evidence.
- [ ] Obtain separate authorization for GitHub Release creation. In GitHub's
  Releases page create the release for the existing `v0.1.0` tag using the finalized
  changelog. Verify the public release points to that exact tag/commit and its notes,
  package link, and documentation link are correct.

## Rollback and recovery

Hex 2.4.2's installed `mix help hex.publish` states that a newly created package
can be reverted or updated within **24 hours** of initial publication; a new
version of an existing package has **one hour**. Confirm current rules immediately
before publishing, and record the publication time and deadline. Documentation
updates have no time limit. Do not assume the initial-package window if the fresh
name check finds an existing package.

If a published candidate is wrong, obtain explicit rollback authorization and use
`mix hex.publish --revert 0.1.0` within the applicable window. Reverting the last
version removes the package. Verify the registry afterward and coordinate any
GitHub Release correction under separate authorization. Outside the allowed
window, use the registry's current retirement process and a new corrected version;
do not reuse a bad tag or assume an immutable version can be replaced. Every source
fix must repeat local qualification and the full hosted gate before another release.
