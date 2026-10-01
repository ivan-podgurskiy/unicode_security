defmodule UnicodeSecurity.DomainLabel do
  @moduledoc """
  Original source span, normalized forms, and security facts for one domain label.

  Offsets and counts refer to the original UTF-8 input. A trailing root may
  contain source characters removed by UTS #46, so its `input` need not be empty.
  Each non-root label has its own policy findings. Invalid labels retain only
  forms known safe to report and leave unavailable security facts `nil`.
  """
  defstruct [
    :index,
    :input,
    :byte_offset,
    :byte_length,
    :codepoint_index,
    :codepoint_count,
    :root?,
    :unicode,
    :ascii,
    :mapped?,
    :valid_idna?,
    :skeleton,
    :scripts,
    :resolved_scripts,
    :mixed_script?,
    :mixed_number?,
    :restriction_level,
    :verdict,
    reasons: []
  ]

  @type t :: %__MODULE__{
          index: non_neg_integer() | nil,
          input: binary() | nil,
          byte_offset: non_neg_integer() | nil,
          byte_length: non_neg_integer() | nil,
          codepoint_index: non_neg_integer() | nil,
          codepoint_count: non_neg_integer() | nil,
          root?: boolean() | nil,
          unicode: binary() | nil,
          ascii: binary() | nil,
          mapped?: boolean() | nil,
          valid_idna?: boolean() | nil,
          skeleton: binary() | nil,
          scripts: [atom()] | nil,
          resolved_scripts: :all | [atom()] | nil,
          mixed_script?: boolean() | nil,
          mixed_number?: boolean() | nil,
          restriction_level: UnicodeSecurity.Result.restriction_level() | nil,
          verdict: UnicodeSecurity.Result.verdict() | nil,
          reasons: [UnicodeSecurity.Reason.t()]
        }
end
