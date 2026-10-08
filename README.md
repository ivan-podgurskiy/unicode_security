# UnicodeSecurity

Pinned Unicode identifier security for Elixir: confusable comparison keys, script and restriction checks, and hostname policy. Unicode 18.0.0 data is final. Runtime calls are pure Elixir, offline, and have no dependencies.

[![CI](https://github.com/ivan-podgurskiy/unicode_security/actions/workflows/ci.yml/badge.svg)](https://github.com/ivan-podgurskiy/unicode_security/actions/workflows/ci.yml)
[![Hex version](https://img.shields.io/hexpm/v/unicode_security.svg)](https://hex.pm/packages/unicode_security)
[![Hex downloads](https://img.shields.io/hexpm/dt/unicode_security.svg)](https://hex.pm/packages/unicode_security)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/unicode_security)
[![Elixir 1.14+](https://img.shields.io/badge/Elixir-1.14%2B-purple?logo=elixir&logoColor=white)](https://hex.pm/docs/elixir)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A skeleton is a comparison key. It is not a canonical identifier, a display replacement, or an authorization decision. Equal skeletons do not prove ownership or intent.

## Installation

Add `unicode_security` to your dependencies:

```elixir
def deps do
  [
    {:unicode_security, "~> 0.1"}
  ]
end
```

## Comparison keys

```elixir
UnicodeSecurity.skeleton("paypal")
#=> "paypal"

# The two visually similar letters are Cyrillic U+0430.
UnicodeSecurity.skeleton("p\u0430yp\u0430l")
#=> "paypal"
```

`skeleton/1` implements `bidiSkeleton(LTR, input)` from UTS #39 revision 34. Inputs are UTF-8 binaries of at most 4,096 bytes. See [Hexdocs](https://hexdocs.pm/unicode_security) for the full key algorithm.

## Policy checks

`check/2` requires `type: :username`, `:tenant_slug`, `:organization_name`, or `:domain`. It returns the original input plus a verdict and reasons. It does not trim, rewrite, or reserve the name.

```elixir
UnicodeSecurity.check("alice-smith", type: :username).verdict
#=> :safe

UnicodeSecurity.check("pay\u200Dpal", type: :username).verdict
#=> :dangerous
```

## Hostnames

Pass `type: :domain` explicitly. Generic skeleton and comparison functions never guess a domain from a dot.

```elixir
result = UnicodeSecurity.check("BÜCHER.例え.", type: :domain)
result.domain.ascii
#=> "xn--bcher-kva.xn--r8jz45g."
```

This is hostname analysis. It does not query DNS, check public suffixes, or parse browser URLs.

## Scope

The package does not:

- turn a skeleton into an identity, storage key, or authorization decision;
- integrate with Ecto in this version;
- claim CONTEXTO coverage or IDNA2008 registration conformance.

Applications keep the original value and decide uniqueness, ownership, and storage.

## License

MIT. See [LICENSE](LICENSE). Unicode data attribution is recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
