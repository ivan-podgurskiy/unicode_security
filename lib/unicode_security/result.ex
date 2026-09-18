defmodule UnicodeSecurity.Result do
  @moduledoc """
  Analysis facts and policy findings for the original input.

  `policy` is the effective preset. Uncomputed facts remain `nil` for partial
  results, while `valid_input?` distinguishes malformed or oversized input from
  fully analyzed input. `domain` is reserved for domain analysis and is `nil`
  for username, tenant-slug and organization-name analysis.

  `input` is unchanged. `scripts` lists observed ordinary Script values;
  `mixed_script?` uses augmented Script_Extensions. `mixed_number?` counts decimal
  zero representatives. `restriction_level` is the raw standards level even when
  profile punctuation changes the policy decision. `skeleton` is a comparison key,
  never a replacement value. `unicode_version` versions these pinned-data facts.

  Malformed UTF-8 and input over 4,096 original bytes have `valid_input?: false`
  and nil scripts, mixed flags, restriction level and skeleton. Empty input has
  `valid_input?: true`, `scripts: []`, false mixed flags, `restriction_level: :ascii`,
  and `skeleton: ""`, plus a high empty-input reason. Policy danger does not make
  `valid_input?` false. There is no public domain fallback in this milestone.

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

  @type input_type :: :username | :tenant_slug | :organization_name
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
          input: binary() | nil,
          type: input_type() | nil,
          policy: preset() | nil,
          verdict: verdict() | nil,
          scripts: [atom()] | nil,
          mixed_script?: boolean() | nil,
          mixed_number?: boolean() | nil,
          restriction_level: restriction_level() | nil,
          skeleton: binary() | nil,
          unicode_version: binary() | nil,
          domain: nil,
          valid_input?: boolean(),
          reasons: [Reason.t()]
        }
end
