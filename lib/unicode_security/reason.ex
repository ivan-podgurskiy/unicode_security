defmodule UnicodeSecurity.Reason do
  @moduledoc """
  A standards fact or policy violation found in the original input.

  Use `code` and `severity` for application logic. `message` is concise text
  for logs, not a localization API, and must not be parsed. `details` contains
  documented reason-specific facts and never input-derived atom keys.

  `byte_offset` and `codepoint_index` are zero-based positions in the original
  input, not grapheme indexes. Global findings have `nil` positions; malformed
  UTF-8 has a `nil` codepoint index because no reliable scalar index exists.
  """

  defstruct [:code, :severity, :message, :byte_offset, :codepoint_index, details: %{}]

  @type code ::
          :invalid_utf8
          | :input_too_long
          | :empty_input
          | :profile_syntax
          | :restricted_character
          | :invalid_join_control_context
          | :disallowed_script
          | :denied_script
          | :default_ignorable
          | :bidi_control
          | :mixed_scripts
          | :mixed_numbers
          | :restriction_level_below_policy
  @type severity :: :info | :low | :medium | :high | :critical
  @type t :: %__MODULE__{
          code: code() | nil,
          severity: severity() | nil,
          message: binary() | nil,
          byte_offset: non_neg_integer() | nil,
          codepoint_index: non_neg_integer() | nil,
          details: map()
        }
end
