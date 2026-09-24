defmodule UnicodeSecurity.Reason do
  @moduledoc """
  A standards fact or policy violation found in the original input.

  Use `code` and `severity` for application logic. `message` is concise text
  for logs, not a localization API, and must not be parsed. `details` contains
  documented reason-specific facts and never input-derived atom keys.

  `byte_offset` and `codepoint_index` are zero-based positions in the original
  input, not grapheme indexes. Global findings have `nil` positions; malformed
  UTF-8 has a `nil` codepoint index because no reliable scalar index exists.
  Reasons sort by original byte offset, code, then deterministic details; global
  findings follow positional findings. Duplicate offset/code/details are removed.

  ## Codes and details

  - `:invalid_utf8`: `%{invalid_byte: byte}`.
  - `:invalid_item_type`: `%{actual_type: type}` where `type` is one of
    `:atom`, `:integer`, `:float`, `:list`, `:tuple`, `:map`, `:bitstring`,
    `:function`, `:pid`, `:port`, or `:reference`. Nil and booleans are atoms;
    structs are maps. Audit items with this code have nil positions.
  - `:input_too_long`: `%{actual_bytes: count, maximum_bytes: 4096}`.
  - `:empty_input`: `%{}`; valid UTF-8 with positions zero.
  - `:profile_syntax`: `%{codepoint: scalar, rule: :whitespace | :punctuation |
    :unsupported_category}`.
  - `:restricted_character`: `%{codepoint: scalar, identifier_types: sorted_types}`;
    original raw status, independent of canonical closure except explicit profile
    punctuation exceptions.
  - `:invalid_join_control_context`, `:default_ignorable`, `:bidi_control`:
    `%{codepoint: scalar}`; join context validity does not suppress the other codes.
  - `:disallowed_script`, `:denied_script`: `%{script: ordinary_script_atom}`;
    one finding per excluded Script_Extensions candidate if none survive.
  - `:mixed_scripts`: `%{scripts: sorted_observed_scripts}` excluding Common/Inherited.
  - `:mixed_numbers`: `%{zero_codepoints: sorted_unique_decimal_zero_scalars}`.
  - `:restriction_level_below_policy`: `%{actual: raw_level, minimum: policy_minimum}`;
    the decision uses membership extended only by explicit punctuation exceptions.
  - `:exact_duplicate`, `:skeleton_collision`, and the three confusable classes:
    `%{indexes: ordered_zero_based_indexes}` in eager batch collections only.

  ## Severities

  | Codes | Strict | Default | Permissive |
  | --- | --- | --- | --- |
  | invalid_item_type, invalid_utf8, input_too_long | critical | critical | critical |
  | empty_input | high | high | high |
  | profile_syntax, restricted_character, invalid_join_control_context, disallowed_script, denied_script | high | high | medium |
  | default_ignorable, bidi_control | critical | high | high |
  | mixed_scripts, mixed_numbers, restriction_level_below_policy | high | medium | low |
  | single_script_confusable, mixed_script_confusable, whole_script_confusable, skeleton_collision | critical | high | medium |
  | exact_duplicate | info | info | info |

  No reasons or only `:info` means safe, `:low`/`:medium` suspicious, and
  `:high`/`:critical` dangerous. Current checks do not emit collision or generic
  confusable findings. Messages are static and contain no complete untrusted input.

  """

  defstruct [:code, :severity, :message, :byte_offset, :codepoint_index, details: %{}]

  @type code ::
          :invalid_item_type
          | :invalid_utf8
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
          | :single_script_confusable
          | :mixed_script_confusable
          | :whole_script_confusable
          | :skeleton_collision
          | :exact_duplicate
  @type severity :: :info | :low | :medium | :high | :critical
  @type syntax_rule :: :whitespace | :punctuation | :unsupported_category
  @type actual_type ::
          :atom
          | :integer
          | :float
          | :list
          | :tuple
          | :map
          | :bitstring
          | :function
          | :pid
          | :port
          | :reference
  @type details ::
          %{}
          | %{actual_type: actual_type()}
          | %{invalid_byte: byte()}
          | %{actual_bytes: non_neg_integer(), maximum_bytes: 4096}
          | %{codepoint: non_neg_integer(), rule: syntax_rule()}
          | %{codepoint: non_neg_integer(), identifier_types: [atom()]}
          | %{codepoint: non_neg_integer()}
          | %{script: atom()}
          | %{scripts: [atom()]}
          | %{zero_codepoints: [non_neg_integer()]}
          | %{indexes: [non_neg_integer()]}
          | %{
              actual: UnicodeSecurity.Result.restriction_level(),
              minimum: UnicodeSecurity.Result.restriction_level()
            }
  @type t :: %__MODULE__{
          code: code() | nil,
          severity: severity() | nil,
          message: binary() | nil,
          byte_offset: non_neg_integer() | nil,
          codepoint_index: non_neg_integer() | nil,
          details: details()
        }
end
