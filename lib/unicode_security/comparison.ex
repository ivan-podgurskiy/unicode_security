defmodule UnicodeSecurity.Comparison do
  @moduledoc """
  Facts about two original identifiers under the pinned Unicode data.

  `left_scripts` and `right_scripts` contain ordinary observed Script properties.
  Resolved scripts contain the augmented Script_Extensions intersection used to
  classify confusables; `:all` denotes wholly neutral input. A matching skeleton
  is a comparison fact, never an identity or authorization verdict.
  """

  defstruct [
    :confusable?,
    :same_skeleton?,
    :class,
    :canonically_equivalent?,
    :left_skeleton,
    :right_skeleton,
    :left_scripts,
    :right_scripts,
    :left_resolved_scripts,
    :right_resolved_scripts,
    :unicode_version,
    mappings: []
  ]

  @type class ::
          :none
          | :single_script_confusable
          | :whole_script_confusable
          | :mixed_script_confusable
  @type resolved_scripts :: :all | [atom()]
  @type skeleton_span :: %{
          codepoint_index: non_neg_integer(),
          codepoint_count: non_neg_integer()
        }
  @type mapping :: %{
          side: :left | :right,
          byte_offset: non_neg_integer(),
          byte_length: pos_integer(),
          codepoint_index: non_neg_integer(),
          codepoint_count: non_neg_integer(),
          codepoints: [non_neg_integer()],
          skeleton_spans: [skeleton_span()],
          mapping: binary()
        }
  @type t :: %__MODULE__{
          confusable?: boolean() | nil,
          same_skeleton?: boolean() | nil,
          class: class() | nil,
          canonically_equivalent?: boolean() | nil,
          left_skeleton: binary() | nil,
          right_skeleton: binary() | nil,
          left_scripts: [atom()] | nil,
          right_scripts: [atom()] | nil,
          left_resolved_scripts: resolved_scripts() | nil,
          right_resolved_scripts: resolved_scripts() | nil,
          unicode_version: binary() | nil,
          mappings: [mapping()]
        }
end
