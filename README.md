# UnicodeSecurity

Pinned Unicode normalization and confusable comparison keys for Elixir.

> **Development status:** Unicode 18 data is currently draft. This package is not
> releasable until the final Unicode 18 data is published and pinned.

Milestone 0 is the data and normalization foundation: strict UTF-8 validation,
pinned NFD, UTS #39 skeleton generation, and compiled source provenance. Runtime
operation is pure Elixir, offline, stateless, and has no dependencies, NIFs,
application processes, file access, network access, or dynamic atom creation.

## Comparison keys

```elixir
UnicodeSecurity.skeleton("paypal")
#=> "paypal"

# The two visually similar letters are Cyrillic U+0430.
UnicodeSecurity.skeleton("p\u0430yp\u0430l")
#=> "paypal"

UnicodeSecurity.unicode_version()
#=> "18.0.0"

UnicodeSecurity.uts39_revision()
#=> 34

UnicodeSecurity.data_manifest().release_status
#=> :draft
```

A skeleton is a comparison key only. Never use one as a canonical identifier,
display text, automatic replacement, or authorization decision. Equal skeletons
do not prove common ownership, impersonation, or malicious intent. Preserve the
original value; applications own identity checks and storage constraints.

`skeleton/1` applies NFD, one confusables mapping pass, then NFD again using the
embedded Unicode tables. It does not case-fold. ASCII is not exempt from
confusables mappings (for example, `"m"` maps to `"rn"`). Output is independent of
the host OTP Unicode tables.

Inputs must be UTF-8 binaries of at most 4,096 bytes. Empty input returns `""`.
Nonbinary input raises `ArgumentError`. Malformed UTF-8 and oversized inputs raise
`UnicodeSecurity.InvalidInputError` with `reason` and a zero-based `byte_offset`;
oversized inputs report offset 4,096. Generated output may exceed 4,096 bytes.

Policy verdicts, identifier profiles, script analysis, IDNA/domain handling,
pairwise classification, collection/batch APIs, and Ecto integration are outside
this milestone. The package does not decide whether an identifier is safe.

## Data and development

Unicode 18.0.0 / UTS #39 revision 34 is pinned as **draft**. The embedded manifest
records each logical source name, URL, version, status, byte count, and SHA-256.
Do not promote a data status or update a hash to silence a verification failure.
An upstream draft change requires a deliberate source update and regeneration.
Persisted keys must retain their Unicode version and be reviewed when data changes.

From a source checkout:

Use Elixir 1.20 / OTP 29 for the development quality gate. Runtime consumers
support Elixir `~> 1.14`; minimum-version test runs use `MIX_ENV=test` to keep
development-only documentation tools out of the compatibility build.

```sh
mix deps.get
mix run scripts/fetch_unicode_data.exs
git diff --exit-code -- priv/unicode/sources.lock
mix run scripts/generate_unicode_data.exs
mix run scripts/check_generated.exs
```

Source fixtures are vendored for offline verification on a fresh checkout.
The acquisition script verifies existing files against the source lock; network
access is needed only if fixtures must be downloaded. The lock-diff check rejects
downloads that no longer match the committed draft. Generation, conformance,
and reproducibility checks run offline. Raw files stay tracked under
`priv/unicode/18.0.0-draft` for these checks and are excluded from Hex.

The compatibility matrix covers Ubuntu Elixir/OTP 1.14/25, 1.17/26, 1.18/27,
1.19/28, and 1.20/29, plus macOS and Windows 1.20/29. Every combination runs
the same normalization conformance and fixed golden-output tests. The primary
Ubuntu 1.20/29 job also runs the quality gate:

```sh
mix compile --warnings-as-errors
mix test --warnings-as-errors
mix test --cover --warnings-as-errors
mix format --check-formatted
mix run scripts/check_generated.exs
mix credo --strict
mix dialyzer --format github
mix docs --warnings-as-errors
mix hex.build
mix run bench/milestone_0.exs
```

The benchmark warms each case and reports medians over 1,000 samples plus
generated source and compiled BEAM sizes. Its fixed inputs make runs comparable;
timing thresholds are not enforced across machines. Compile time can be measured
with `time mix compile --force --warnings-as-errors`. Inspect the built Hex
archive before release; it contains runtime source, generated tables, package
configuration, and public documentation, with a target below 5 MB unpacked.

## Publication readiness

`mix hex.build` is allowed for local inspection while data is draft. It does not
certify publication readiness. Before any publication, maintainers must run:

```sh
# Release-workflow prerequisite: run manually before publication.
mix run scripts/check_release_data.exs
```

<!-- A future release workflow must run scripts/check_release_data.exs before
publication. Do not run this intentional draft-data failure in ordinary CI.
Milestone 0 has no publish workflow and must not be tagged or published. -->

The release check first verifies generated data, then exits with
`release blocked: Unicode 18.0.0 data status is draft`. It must continue to fail
until a coordinated update pins final data. This milestone is not published.

## License

MIT. See [LICENSE](LICENSE). Unicode data attribution is recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
