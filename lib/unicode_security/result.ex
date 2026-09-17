defmodule UnicodeSecurity.Result do
  @moduledoc """
  Analysis facts and policy findings for the original input.

  `policy` is the effective preset. Uncomputed facts remain `nil` for partial
  results, while `valid_input?` distinguishes malformed or oversized input from
  fully analyzed input. `domain` is reserved for domain analysis and is `nil`
  for username, tenant-slug and organization-name analysis.

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
