# UnicodeSecurity

Pinned Unicode normalization, confusable comparison keys, and script detection for Elixir.

> **Development status:** Unicode 18 data is currently draft. This package is not
> releasable until the final Unicode 18 data is published and pinned.

Milestone 0 is the data and normalization foundation: strict UTF-8 validation,
pinned NFD, UTS #39 skeleton generation, and compiled source provenance. Milestone 1
adds script properties and mixed-script detection. Runtime
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

`skeleton/1` implements `bidiSkeleton(LTR, input)` from
[UTS #39 revision 34, section 4](https://www.unicode.org/reports/tr39/tr39-34.html#Confusable_Detection).
It applies the Unicode Bidirectional Algorithm through L2 with paragraph level
0, restores combining marks after their bases (L3), and applies character-based
mirroring (L4). It then applies NFD, removes `Default_Ignorable_Code_Point`,
substitutes MA prototypes, and reapplies NFD. For example, `"pay\u200Dpal"`
and `"paypal"` produce the same key. It does not case-fold. ASCII also has
confusables mappings (`"m"` maps to `"rn"`). All behavior uses embedded data.

The bidi implementation follows
[UAX #9 revision 51](https://www.unicode.org/reports/tr9/tr9-51.html), the algorithm
referenced by UTS #39 revision 34. It processes each P1 paragraph as one line,
without display-width wrapping. U+2028 retains its pinned `WS` bidi class.
X9 removes boundary neutrals (including NUL and noncharacters) as well as its
specified formatting controls. When a mirrored character has no encoded
`Bidi_Mirroring_Glyph` counterpart, its scalar is retained.

The internal prototype transform is idempotent. The full bidi skeleton need
not be: applying it again can reverse an RTL run again. Similarly, applying
bidi preprocessing to a multi-character MA prototype can differ from applying
it to the original single character. Always compute keys from the original
identifier, not from a previously computed key.

Inputs must be UTF-8 binaries of at most 4,096 bytes. Empty input returns `""`.
Nonbinary input raises `ArgumentError`. Malformed UTF-8 and oversized inputs raise
`UnicodeSecurity.InvalidInputError` with `reason` and a zero-based `byte_offset`;
oversized inputs report offset 4,096. Generated output may exceed 4,096 bytes.

Policy verdicts, identifier profiles, IDNA/domain handling,
pairwise classification, collection/batch APIs, and Ecto integration are outside
this milestone. The package does not decide whether an identifier is safe.

## Script detection

```elixir
UnicodeSecurity.scripts("раypal")
#=> [:cyrillic, :latin]

UnicodeSecurity.scripts("a \u0301")
#=> [:common, :inherited, :latin]

UnicodeSecurity.mixed_script?("раypal")
#=> true

UnicodeSecurity.mixed_script?("ねガ")
#=> false
```

`scripts/1` reports sorted, unique **Script** property values from the original
input as lowercase snake-case atoms. It includes Common, Inherited, and Unknown;
empty input returns `[]`. No normalization or skeleton transform is applied.

`mixed_script?/1` implements
[UTS #39 revision 34, section 5.1](https://www.unicode.org/reports/tr39/tr39-34.html#Mixed_Script_Detection):
intersect the augmented **Script_Extensions** sets, treating Common/Inherited
extension values as neutral. Augmentation supports Han with Latin (`Hntl`),
Japanese (`Jpan`), Korean (`Kore`), and Han with Bopomofo (`Hanb`). Thus `"ねガ"`
and `"漢a"` are single-script under this definition, although their ordinary
Script properties differ. Empty or wholly neutral input returns `false`.
An explicit extension set takes precedence over the ordinary property;
for example, `"aー"` is mixed even though U+30FC has Script=Common.

Both APIs share the 4,096-byte UTF-8 input limit and original-input errors
described above. Neither decides identifier validity or whether a name is safe.
The pinned sources are `Scripts.txt`, `ScriptExtensions.txt`, and
`PropertyValueAliases.txt`; see
[UAX #24](https://www.unicode.org/reports/tr24/) for property definitions.

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
access is needed only if fixtures must be downloaded. A surviving lock remains
authoritative when the fixture directory is missing: all staged downloads must
match its byte sizes and hashes before installation, and the lock is preserved.
Initial lock creation requires `--create-lock`; deliberate upstream updates
require `--update-lock`, followed by review and regeneration. Generation, conformance,
and reproducibility checks run offline. Raw files stay tracked under
`priv/unicode/18.0.0-draft` for these checks and are excluded from Hex.

The bidi inputs are `extracted/DerivedBidiClass.txt` (including unassigned-code-point
defaults), `BidiBrackets.txt`, `BidiMirroring.txt`, and `DerivedCoreProperties.txt`.
The existing `UnicodeData.txt` also supplies nonspacing/enclosing mark categories.
All have versioned Unicode 18.0.0 UCD URLs in the manifest. The exact
`BidiMirroring-18.0.0.txt` source retains an upstream comment identifying its
carried-forward Unicode 17 repertoire; that comment has not been rewritten.

Tests cover all 490,846 rows of `BidiTest.txt` in every declared paragraph
direction and all 91,707 rows of `BidiCharacterTest.txt`, through L2. Separate
tests cover P1, L3, L4, the revision-34 LTR-confusable example, and public golden
bytes. All 6,712 MA records verify the prototype transform, alongside the full
normalization corpus and canonical-equivalence/idempotence properties applicable
to each algorithm.

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
