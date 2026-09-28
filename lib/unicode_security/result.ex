defmodule UnicodeSecurity.Result do
  @moduledoc """
  Analysis facts and policy findings for the original input.

  `policy` is the effective preset. Uncomputed facts remain `nil` for partial
  results, while `valid_input?` distinguishes malformed, oversized, or invalid
  domain input from fully analyzed input. `domain` holds original-label and IDNA
  facts for explicit domain analysis and is `nil` for other types.

  `input` is unchanged, including nonbinary items in an audit. `scripts` lists observed ordinary Script values;
  `mixed_script?` uses augmented Script_Extensions. `mixed_number?` counts decimal
  zero representatives. `restriction_level` is the raw standards level even when
  profile punctuation changes the policy decision. `skeleton` is a comparison key,
  never a replacement value. `unicode_version` versions these pinned-data facts.

  Nonbinary audit items, malformed UTF-8 and input over 4,096 original bytes have `valid_input?: false`
  and nil scripts, mixed flags, restriction level and skeleton. Empty input has
  `valid_input?: true`, `scripts: []`, false mixed flags, `restriction_level: :ascii`,
  and `skeleton: ""`, plus a high empty-input reason for generic types. Domain
  input must pass IDNA and hostname validity before whole-name facts or a key
  are available. Policy danger alone does not make `valid_input?` false.

  The highest reason severity determines `verdict`. Field meanings and the
  documented atom values are public contracts.
  """

  alias UnicodeSecurity.Reason

  defstruct [
    :input,
    :type,
    :policy,
    :verdict,
    :scripts,
    :mixed_script?,
    :mixed_number?,
    :restriction_level,
    :skeleton,
    :unicode_version,
    :domain,
    valid_input?: true,
    reasons: []
  ]

  @type input_type :: :username | :tenant_slug | :organization_name | :domain
  @type preset :: :strict | :default | :permissive
  @type verdict :: :safe | :suspicious | :dangerous
  @type restriction_level ::
          :ascii
          | :single_script_restrictive
          | :highly_restrictive
          | :moderately_restrictive
          | :minimally_restrictive
          | :unrestricted

  @type t :: %__MODULE__{
          input: term(),
          type: input_type() | nil,
          policy: preset() | nil,
          verdict: verdict() | nil,
          scripts: [atom()] | nil,
          mixed_script?: boolean() | nil,
          mixed_number?: boolean() | nil,
          restriction_level: restriction_level() | nil,
          skeleton: binary() | nil,
          unicode_version: binary() | nil,
          domain: UnicodeSecurity.DomainResult.t() | nil,
          valid_input?: boolean(),
          reasons: [Reason.t()]
        }
end
