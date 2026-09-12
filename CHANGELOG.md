# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- Milestone 0 foundation with strict UTF-8 validation and a 4,096-byte input limit.
- Pinned Unicode 18.0.0 canonical decomposition, combining-class ordering, and
  algorithmic Hangul decomposition, independent of host OTP Unicode tables.
- UTS #39 revision 34 confusable skeleton comparison keys, including NFD before
  and after a single mapping pass.
- Compiled draft-data provenance with source URLs, versions, byte sizes, and
  SHA-256 hashes; locked acquisition and deterministic offline regeneration.
- Normalization conformance, property tests, fixed golden outputs, compatibility
  CI for Elixir 1.14–1.20 / OTP 25–29, and benchmark/package-size reporting.
- Quality gates and a manual pre-publication check that intentionally blocks
  draft Unicode data. No release or publish workflow is provided.

### Limitations

- Unicode 18.0.0 sources remain draft; this milestone is not releasable.
- Skeletons are comparison keys only, never replacements or authorization
  decisions. Policy, profiles, domains/IDNA, batch APIs, and Ecto are not included.

[0.1.0]: https://github.com/ivan-podgurskiy/unicode_security/releases/tag/v0.1.0
