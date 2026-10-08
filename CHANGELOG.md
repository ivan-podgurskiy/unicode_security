# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-08

### Added

- `UnicodeSecurity.skeleton/1` comparison keys from pinned Unicode 18.0.0 data, using UTS #39 revision 34 `bidiSkeleton(LTR, input)`.
- Script, mixed-script, mixed-number, and restriction-level detection.
- Identifier status, identifier types, and canonically closed General Security Profile membership.
- `check/2` policy results for `:username`, `:tenant_slug`, `:organization_name`, and `:domain`, with strict, default, and permissive presets.
- Explicit `type: :domain` hostname checks using pinned UTS #46 revision 36 nontransitional processing, including an optional final root and DNS length limits.
- Comparison, conflict keys, existing-set conflict checks, lazy audit, and batch duplicate and collision groups.
- Zero runtime dependencies. Supported Elixir is `~> 1.14`.

### Limitations

- Skeletons are comparison keys only. They are not replacements or authorization decisions.
- Domain analysis covers hostnames. It does not perform DNS lookup, public-suffix checks, browser URL parsing, CONTEXTO, or IDNA2008 registration.
- Ecto integration is not in this version.

[0.1.0]: https://github.com/ivan-podgurskiy/unicode_security/releases/tag/v0.1.0
