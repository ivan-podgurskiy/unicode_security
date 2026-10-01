# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- Explicit `type: :domain` hostname checks using pinned Unicode 18 UTS #46
  revision 36 nontransitional processing, per-label policy facts and source spans,
  optional final root, DNS byte limits, partial invalid results and stable reasons.
- Domain-aware comparison keys, original-label evidence, conflicts, lazy audit,
  and correlated batch classes; literal public contracts and a source-free
  runtime acceptance test cover the new modules.
- Milestone 4 hostname and batch benchmark. The IDNA mapping and conformance
  sources are individually final; the combined Unicode 18 release remains draft.
- Pairwise comparison, type-scoped conflict keys and existing-set conflict checks
  with original scalar-to-skeleton mapping evidence and all three confusable classes.
- Lazy indexed audit and eager batch analysis with separate exact duplicates and
  skeleton collisions, ordered groups, collection reasons and literal contracts.
- Milestone 3 collection benchmark and source-free acceptance for the new runtime APIs.
- Original-input `check/2` Results and structured Reasons for username, tenant slug,
  and organization name profiles, with strict/default/permissive policies, script
  overrides, deterministic positions/order and explicit punctuation exceptions.
- Normative UTS #39 revision 34 join-control contexts on internal pinned NFC;
  four additional locked draft sources bring provenance to 19 sources.
- Complete literal versioned policy goldens, source-free runtime acceptance and
  warmed profile benchmarks including ASCII MA mappings and 4,096-byte cases.

- UTS #39 revision 34 mixed-decimal-number detection and ordered restriction levels,
  using the canonically closed General Security Profile, augmented script sets, and
  the frozen UAX #31 revision 44 Recommended scripts; no policy or syntax exceptions.
- Exact UTS #39 Identifier_Status and Identifier_Type scalar lookups, plus
  canonically closed General Security Profile membership with no syntax exceptions.
- Script property reporting with `scripts/1` and UTS #39 revision 34 augmented
  Script_Extensions detection with `mixed_script?/1`, using three additional
  locked Unicode 18 sources and preserving existing hashes.
- Milestone 0 foundation with strict UTF-8 validation and a 4,096-byte input limit.
- Pinned Unicode 18.0.0 canonical decomposition, combining-class ordering, and
  algorithmic Hangul decomposition, independent of host OTP Unicode tables.
- UTS #39 revision 34 `bidiSkeleton(LTR, input)` comparison keys: complete pinned
  bidi reordering, combining-mark placement, mirroring, NFD, default-ignorable
  removal, one MA mapping pass, and NFD again.
- Compiled draft-data provenance with source URLs, versions, byte sizes, and
  SHA-256 hashes; locked acquisition and deterministic offline regeneration.
- Normalization conformance, property tests, fixed golden outputs, compatibility
  CI for Elixir 1.14–1.20 / OTP 25–29, and benchmark/package-size reporting.
- Quality gates and a manual pre-publication check that intentionally blocks
  draft Unicode data. No release or publish workflow is provided.

### Fixed

- Corrected the development skeleton pipeline to revision-34 semantics; keys
  can change for bidi text, controls, noncharacters, and default-ignorables.
  Recompute any keys created with the earlier development implementation.
- Recovery of missing source fixtures verifies staged downloads against the
  existing lock before installation. Lock creation and updates require explicit
  maintainer flags.

### Limitations

- Unicode 18.0.0 sources remain draft; this milestone is not releasable.
- Skeletons are comparison keys only, never replacements or authorization
  decisions. Domain analysis covers hostnames, not DNS, public suffixes, browser
  URLs, CONTEXTO or IDNA2008 registration. Ecto integration remains future work.

[0.1.0]: https://github.com/ivan-podgurskiy/unicode_security/releases/tag/v0.1.0
