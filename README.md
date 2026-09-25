# UnicodeSecurity

Pinned Unicode normalization, confusable comparison keys, script detection, and
identifier security properties and policy checks for Elixir.

> **Development status:** Unicode 18 data is currently draft. This package is not
> releasable until the final Unicode 18 data is published and pinned.

Milestone 0 is the data and normalization foundation: strict UTF-8 validation,
pinned NFD, UTS #39 skeleton generation, and compiled source provenance. Milestone 1
adds script properties, mixed-script and mixed-number detection, UTS #39 identifier
profile membership, and restriction levels. Runtime
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

IDNA/domain handling and Ecto integration are planned later. The comparison and
collection APIs below support the three current identifier profiles.

## Compare names and inspect existing collections

```elixir
UnicodeSecurity.compare("m", "rn").class
#=> :single_script_confusable
UnicodeSecurity.same_skeleton?("é", "e\u0301")
#=> true
UnicodeSecurity.confusable?("é", "e\u0301")
#=> false (canonical equivalence is not a confusable class)

key = UnicodeSecurity.conflict_key("m", type: :username)
#=> "rn"
# Store the original identifier, key and Unicode version alongside an
# application-owned unique index on the namespace and chosen identity column.
UnicodeSecurity.conflicts?("m", ["rn", "unvisited"], type: :username)
#=> true; stops at the first match
UnicodeSecurity.conflicts("m", ["x", "rn", "m"], type: :username)
#=> indexed Conflict structs for the matches at positions 1 and 2
```

`compare/2,3` returns two skeletons, canonical equivalence, observed ordinary
Script lists, resolved augmented Script_Extensions sets, a class and original-input
mapping evidence. `:all` denotes entirely neutral input; `[]` denotes an empty
resolved intersection. A mapping records original zero-based byte offset and scalar
index, the source scalar, its contribution and target skeleton spans in **scalar**
coordinates. Removed scalars keep a mapping with empty spans. Reordering can split
one source contribution into noncontiguous spans. The aggregate class is `:none`,
`:single_script_confusable`, `:whole_script_confusable` or
`:mixed_script_confusable`. Canonical equality has class `:none`.

`compare/3`, `conflict_key/2`, `conflicts?/3` and `conflicts/3` accept only the
`type` option (`:username`, `:tenant_slug`, `:organization_name`); they do not
accept a policy preset or script overrides. The three current types use the same
key. Invalid options fail before input validation. Inputs validate left to right;
for existing collections the candidate validates before the enumerable. Visited
existing values must be valid UTF-8 binaries within 4,096 bytes. `conflicts?/3`
stops at the first match; `conflicts/3` consumes all values and retains repeated
matches at their original indexes. Neither checks ownership or reserves a name.
Preflight conflicts can race with writes, so the application still needs storage
constraints and a transaction appropriate to its identity rules. Keep the original
name and recompute/version stored keys when pinned Unicode data changes.

```elixir
batch = UnicodeSecurity.check_many(["m", "m", "rn"], type: :username)
#=> one exact duplicate at [0, 1] and one skeleton collision at [0, 1, 2]
Enum.map(batch.duplicates, & &1.indexes)
#=> [[0, 1]]
Enum.map(batch.collisions, & &1.indexes)
#=> [[0, 1, 2]]

UnicodeSecurity.check_many(["é", "e\u0301"], type: :username).collisions
#=> one canonical-only key collision (class :none)

UnicodeSecurity.audit(Stream.iterate(0, &(&1 + 1)), type: :tenant_slug)
|> Enum.take(3)
#=> three indexed BatchItems with invalid_item_type results; finite consumption
```

`audit/2` returns a lazy stream; configuration is checked at call time and items
are checked only when consumed. A nonbinary item yields an `:invalid_item_type`
Result with the original term preserved. Producer exceptions propagate. `check_many/2`
eagerly consumes the enumerable and returns unchanged per-item Results plus ordered
groups. Exact binary duplicates include invalid UTF-8 and oversized binaries;
only valid inputs with a skeleton join collision groups. A collision requires two
distinct original binaries; canonical-only collisions have class `:none`. A group
can contain multiple classes, ordered by precedence `:mixed_script_confusable`,
`:whole_script_confusable`, `:single_script_confusable`; its `class` is the first.
Collection reasons carry group indexes and have preset severity critical/high/medium
for strict/default/permissive collision findings, while exact duplicates have
`:info`. They do not alter any per-item Result or verdict. Neither batch findings
nor a safe per-item result decide identity, ownership or authorization.

## Policy checks

`check/2` analyzes untrusted original input without trimming, case folding,
rewriting, or changing the stored name. Applications choose a profile and decide
how to handle the returned verdict and reasons. A safe verdict describes this
policy check; it does not establish identity, intent, authorization, or uniqueness.
Skeleton equality is only a comparison signal. Keep the original value and version
any persisted skeletons.

```elixir
UnicodeSecurity.check("alice-smith", type: :username).verdict
#=> :safe

UnicodeSecurity.check("pay\u200Dpal", type: :username).verdict
#=> :dangerous

UnicodeSecurity.check("Acme & Co.", type: :organization_name).verdict
#=> :suspicious

UnicodeSecurity.check("раypal", type: :username, allowed_scripts: [:latin]).verdict
#=> :dangerous
```

The required `type` is `:username`, `:tenant_slug`, or `:organization_name`.
`:domain` raises `ArgumentError` until the dedicated IDNA/domain pipeline lands.
Ecto integration is also planned later. Profiles have no first-character,
case, length-in-characters, or business naming rules:

| Type | Accepted syntax | Identifier_Status exceptions | Default policy |
| --- | --- | --- | --- |
| `:username` | Unicode letters L*, marks M*, decimal digits Nd; ASCII `_-.` | `_-.` | `:default` |
| `:tenant_slug` | L*, M*, Nd; ASCII `-` | `-` | `:default` |
| `:organization_name` | L*, M*, Nd; pinned White_Space; punctuation Pc/Pd/Ps/Pe/Pi/Pf/Po | none | `:permissive` |

ZWJ and ZWNJ use the normative UTS #39 revision 34 §3.1.1.1 context rules on
internal pinned NFC, rather than generic syntax or IDNA CONTEXTJ rules. Internal
NFC is implementation support, not a public normalization API. A valid join context
suppresses only `invalid_join_control_context`: joiners still produce Restricted
and default-ignorable findings. Organization whitespace syntax also preserves all
status and control findings. Symbols and other unsupported categories produce
`profile_syntax`. Even ASCII input can contain restricted characters or MA mappings.

Raw facts (`scripts`, `mixed_script?`, `mixed_number?`, `restriction_level`,
`skeleton`) retain the standards primitive meanings. Per-scalar restrictions refer
to the exact original scalars. Thus `"ĕ"` has raw Restricted/Uncommon_Use status
and a restricted-character finding, while `"e\u0306"` uses Allowed scalars and
has no such finding; both have canonically allowed membership and equal skeletons.
The default verdicts are dangerous and safe, respectively. Permissive makes the
composed form suspicious. Organization `"Acme & Co."` permits spaces and `&`
syntactically but reports their raw Restricted status, making it suspicious under
its default permissive preset.

These are deliberate UTS #39 policy-layer modifications: username `_-.` and tenant
`-` are explicit status exceptions and extend policy membership by checking runs
separated by exception punctuation. Separators remain normalization boundaries,
so Hangul Jamo or combining sequences cannot compose across punctuation. The raw
restriction level is preserved; the below-policy decision uses the extended
membership. Organization syntax permissions never extend status membership.
Raw scalar diagnostic restrictions are independent of whole-string canonical
closure. Standards primitives themselves add no profile exceptions.

All three policies work with all three types. Ordered restriction levels are
`:ascii`, `:single_script_restrictive`, `:highly_restrictive`,
`:moderately_restrictive`, `:minimally_restrictive`, `:unrestricted`. Minimums are
`:highly_restrictive` for strict, `:moderately_restrictive` for default, and
`:minimally_restrictive` for permissive. Mixed-number findings remain independent.

| Reason code | Details | Strict | Default | Permissive |
| --- | --- | --- | --- | --- |
| `invalid_utf8` | `%{invalid_byte: integer}` | critical | critical | critical |
| `input_too_long` | `%{actual_bytes: integer, maximum_bytes: 4096}` | critical | critical | critical |
| `empty_input` | `%{}` | high | high | high |
| `profile_syntax` | `%{rule: :whitespace \| :punctuation \| :unsupported_category, codepoint: scalar}` | high | high | medium |
| `restricted_character` | `%{codepoint: scalar, identifier_types: sorted_types}` | high | high | medium |
| `invalid_join_control_context` | `%{codepoint: scalar}` | high | high | medium |
| `disallowed_script` | `%{script: ordinary_script_atom}` | high | high | medium |
| `denied_script` | `%{script: ordinary_script_atom}` | high | high | medium |
| `default_ignorable` | `%{codepoint: scalar}` | critical | high | high |
| `bidi_control` | `%{codepoint: scalar}` | critical | high | high |
| `mixed_scripts` | `%{scripts: sorted_observed_scripts_without_common_inherited}` | high | medium | low |
| `mixed_numbers` | `%{zero_codepoints: sorted_unique_decimal_zero_scalars}` | high | medium | low |
| `restriction_level_below_policy` | `%{actual: raw_level, minimum: policy_minimum}` | high | medium | low |

The highest severity determines verdict: no findings or only info → safe;
low/medium → suspicious; high/critical → dangerous. Current checks emit the 13
codes above, no collision or generic confusable finding. Use codes and structured
details for logic. Messages are static, concise text, never the entire untrusted
input, and are not a localization or parsing API.

`UnicodeSecurity.Result` preserves `input`, `type`, effective preset `policy`,
`unicode_version: "18.0.0"`, and `domain: nil`. Every binary with valid configuration
returns a Result, including malformed or oversized input. More than 4,096 original
bytes is rejected before decoding with one critical reason at byte 4,096 and a nil
scalar index. Invalid UTF-8 returns one critical reason at the decoder's original
byte offset and a nil scalar index. Both have `valid_input?: false` and nil
`scripts`, `mixed_script?`, `mixed_number?`, `restriction_level`, `skeleton`.
Empty input is valid UTF-8: `valid_input?: true`, empty scripts/skeleton, false mixed
flags and `:ascii` level, plus a high reason at byte/scalar index zero. A false
`valid_input?` describes decoding/size failure; policy danger does not make it false.

Scalar reasons have original zero-based byte offsets and scalar indexes, not
normalized or grapheme positions. Global mixed and below-policy findings have nil
positions and follow all positional reasons. Sorting is byte offset, code atom,
then deterministic details (including script atom/codepoint ties); global findings
sort by code and details. Duplicate offset/code/details findings are removed.

Configuration is validated before content. Nonbinary input, missing/unsupported
type or policy, unknown/duplicate options, malformed keyword/list values, unknown
script atoms, or intersecting allow/deny lists raise `ArgumentError`. Allowed keys
are only `type`, `policy`, `allowed_scripts`, `denied_scripts`. Script lists are
proper lists, deduplicated and sorted; no input-derived atoms are created.

Script overrides use ordinary Script_Extensions (falling back to Script),
independently of UTS #39 augmented mixed-script/restriction facts. An omitted
allowlist is unrestricted; explicit `allowed_scripts: []` permits only neutral
scalars. Exactly Common/Inherited-only candidates are neutral. Listing `:common`
or `:inherited` does not authorize other scripts. Intersect each non-neutral
candidate set with the allowlist and then subtract denied scripts. One surviving
candidate accepts a multivalued scalar; otherwise emit one finding per excluded
candidate, with original positions. For example, `"ー"` has Hiragana/Katakana
extensions: denying only Hiragana passes, denying both produces two findings.
U+0301 has multivalued pinned extensions and is not neutral solely because its
ordinary Script is Inherited. Synthetic `:jpan`, `:kore`, `:hanb`, `:hntl` names
are not accepted options. The supported closed ordinary names are listed below.

```text
:adlam, :ahom, :anatolian_hieroglyphs, :arabic, :armenian, :avestan, :balinese, :bamum,
:bassa_vah, :batak, :bengali, :beria_erfe, :bhaiksuki, :bopomofo, :brahmi, :braille, :buginese,
:buhid, :canadian_aboriginal, :carian, :caucasian_albanian, :chakma, :cham, :cherokee,
:chorasmian, :common, :coptic, :cuneiform, :cypriot, :cypro_minoan, :cyrillic, :deseret,
:devanagari, :dives_akuru, :dogra, :duployan, :egyptian_hieroglyphs, :elbasan, :elymaic,
:ethiopic, :garay, :georgian, :glagolitic, :gothic, :grantha, :greek, :gujarati,
:gunjala_gondi, :gurmukhi, :gurung_khema, :han, :hangul, :hanifi_rohingya, :hanunoo, :hatran,
:hebrew, :hiragana, :imperial_aramaic, :inherited, :inscriptional_pahlavi,
:inscriptional_parthian, :javanese, :jurchen, :kaithi, :kannada, :katakana,
:katakana_or_hiragana, :kawi, :kayah_li, :kharoshthi, :khitan_small_script, :khmer, :khojki,
:khudawadi, :kirat_rai, :lao, :latin, :lepcha, :limbu, :linear_a, :linear_b, :lisu, :lycian,
:lydian, :mahajani, :makasar, :malayalam, :mandaic, :manichaean, :marchen, :masaram_gondi,
:medefaidrin, :meetei_mayek, :mende_kikakui, :meroitic_cursive, :meroitic_hieroglyphs, :miao,
:modi, :mongolian, :mro, :multani, :myanmar, :nabataean, :nag_mundari, :nandinagari,
:new_tai_lue, :newa, :nko, :nushu, :nyiakeng_puachue_hmong, :ogham, :ol_chiki, :ol_onal,
:old_hungarian, :old_italic, :old_north_arabian, :old_permic, :old_persian, :old_sogdian,
:old_south_arabian, :old_turkic, :old_uyghur, :oriya, :osage, :osmanya, :pahawh_hmong,
:palmyrene, :pau_cin_hau, :phags_pa, :phoenician, :proto_cuneiform, :psalter_pahlavi, :rejang,
:runic, :samaritan, :saurashtra, :seal, :sharada, :shavian, :siddham, :sidetic, :signwriting,
:sinhala, :sogdian, :sora_sompeng, :soyombo, :sundanese, :sunuwar, :syloti_nagri, :syriac,
:tagalog, :tagbanwa, :tai_le, :tai_tham, :tai_viet, :tai_yo, :takri, :tamil, :tangsa, :tangut,
:telugu, :thaana, :thai, :tibetan, :tifinagh, :tirhuta, :todhri, :tolong_siki, :toto,
:tulu_tigalari, :ugaritic, :unknown, :vai, :vithkuqi, :wancho, :warang_citi, :yezidi, :yi,
:zanabazar_square
```

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

## Identifier status and type

```elixir
UnicodeSecurity.identifier_status(?a)
#=> :allowed

UnicodeSecurity.identifier_types(0x200D)
#=> [:default_ignorable]

UnicodeSecurity.allowed_identifier?("paypal")
#=> true

UnicodeSecurity.allowed_identifier?("pay\u200Dpal")
#=> false
```

`identifier_status/1` and `identifier_types/1` report exact scalar properties from
the pinned UTS #39 data. They accept only integer Unicode scalar values; surrogates,
out-of-range integers, and other terms raise `ArgumentError`. Identifier_Status
defaults to `:restricted`; Identifier_Type defaults to `[:not_character]`. Type sets
are sorted lowercase snake-case atoms from a closed literal set.

`allowed_identifier?/1` tests membership in the canonically closed
[UTS #39 General Security Profile](https://www.unicode.org/reports/tr39/tr39-34.html#General_Security_Profile).
It accepts when some canonically equivalent representation contains only Allowed
characters. Consequently, exact scalar status and string membership deliberately
differ: U+0115 is Restricted, while both `"ĕ"` and its decomposition `"e\u0306"`
are accepted. The implementation uses pinned NFD data, generated explicit-composition
rescues, algorithmic Hangul composition, and bounded suffix dynamic programming;
it does not use host Unicode properties.

This predicate adds no application syntax exceptions and does not validate identifier
grammar. Empty input is vacuously allowed. It shares the 4,096-byte UTF-8 limit and
original-input errors described above.

## Numbers and restriction levels

```elixir
UnicodeSecurity.mixed_number?("1١")
#=> true

UnicodeSecurity.restriction_level("paypal")
#=> :ascii

UnicodeSecurity.restriction_level("aねガ")
#=> :highly_restrictive

UnicodeSecurity.restriction_level("pay\u200Dpal")
#=> :unrestricted
```

`mixed_number?/1` follows
[UTS #39 revision 34, section 5.3](https://www.unicode.org/reports/tr39/tr39-34.html#Mixed_Number_Detection),
counting distinct decimal systems by their zero scalar (`scalar - decimal value`)
from pinned `UnicodeData.txt` Nd records. Non-Nd numeric characters, such as fractions,
Roman numerals, and circled numbers, do not introduce systems. Empty input returns
`false`. This is detection, not an identifier syntax validator.

`restriction_level/1` follows
[UTS #39 revision 34, section 5.2](https://www.unicode.org/reports/tr39/tr39-34.html#Restriction_Level_Detection).
It first tests canonically closed General Security Profile membership; outside-profile
strings return `:unrestricted`, even if ASCII or single-script. It then returns the
first applicable level: `:ascii`, `:single_script_restrictive`, `:highly_restrictive`,
`:moderately_restrictive`, or `:minimally_restrictive`. Empty input returns `:ascii`.
Script detection uses resolved augmented Script_Extensions, not the ordinary observed
Script list. For mixed strings, whole script-set entries containing Latin are removed
before checking CJK coverage and the remaining script intersection.

The Recommended set is frozen from
[UAX #31 revision 44, Table 5](https://www.unicode.org/reports/tr31/tr31-44.html#Table_Recommended_Scripts)
(Unicode 18.0.0 proposed): Common, Inherited, Arabic, Armenian, Bengali, Cyrillic,
Devanagari, Ethiopic, Georgian, Greek, Gujarati, Gurmukhi, Hangul, Han, Hebrew,
Hiragana, Katakana, Kannada, Khmer, Lao, Latin, Malayalam, Myanmar, Oriya, Sinhala,
Tamil, Telugu, Thaana, Thai, and Tibetan. Greek and Cyrillic are excluded from the
moderately restrictive mixed-script test. Bopomofo has been Limited Use since Unicode
17, and its restricted profile scalars return `:unrestricted` before CJK coverage.

These APIs share the 4,096-byte UTF-8 limit and original-input errors. Neither adds
syntax rules, application profile exceptions, or a safety/authorization verdict.
Mixed numbers do not change the restriction level; use their separate predicate.

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

Identifier properties come from the pinned draft `IdentifierStatus.txt` and
`IdentifierType.txt` files. The bidi inputs are `extracted/DerivedBidiClass.txt` (including unassigned-code-point
defaults), `BidiBrackets.txt`, `BidiMirroring.txt`, and `DerivedCoreProperties.txt`.
The existing `UnicodeData.txt` also supplies nonspacing/enclosing mark categories.
All have versioned Unicode 18.0.0 UCD URLs in the manifest. The 19 locked sources
also include DerivedNormalizationProps.txt, PropList.txt,
extracted/DerivedJoiningType.txt, and IndicSyllabicCategory.txt for pinned NFC
composition, whitespace, bidi controls, joining types and Indic join contexts. The exact
`BidiMirroring-18.0.0.txt` source retains an upstream comment identifying its
carried-forward Unicode 17 repertoire; that comment has not been rewritten.

Tests cover all 490,846 rows of `BidiTest.txt` in every declared paragraph
direction and all 91,707 rows of `BidiCharacterTest.txt`, through L2. Separate
tests cover P1, L3, L4, the revision-34 LTR-confusable example, and public golden
bytes. All 6,712 MA records verify the prototype transform, alongside the full
normalization corpus and canonical-equivalence/idempotence properties applicable
to each algorithm.

The configured compatibility matrix covers Ubuntu Elixir/OTP 1.14/25, 1.17/26, 1.18/27,
1.19/28, and 1.20/29, plus macOS and Windows 1.20/29. Hosted matrix results remain pending an authorized remote run. Local minimum
compatibility verification uses Elixir 1.14 / OTP 26; it is not OTP 25 evidence.
Every configured combination runs the same normalization conformance and fixed golden-output tests. The primary
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
mix run bench/milestone_2.exs
mix run bench/milestone_3.exs
```

Milestone 2 warms each case and reports medians over 1,000 samples plus
generated source and compiled BEAM sizes. Milestone 3 uses five warmups and 20
samples, reporting time, process reductions, output bytes, a result checksum and
memory after GC for comparison, streamed conflicts, 1k/2k/4k batches and a finite
audit prefix. Fixed inputs make runs comparable; timing thresholds are not enforced
across machines. Milestone 2 targets a warmed
64-byte ASCII `check/2` median below 100 µs and includes both repeated MA-mapped
ASCII and varied profile syntax, international names and 4,096-byte worst cases.
Compile time can be measured
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
This development milestone has no publish workflow and must not be tagged or published. -->

The release check first verifies generated data, then exits with
`release blocked: Unicode 18.0.0 data status is draft`. It must continue to fail
until a coordinated update pins final data. This milestone is not published.

## License

MIT. See [LICENSE](LICENSE). Unicode data attribution is recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
