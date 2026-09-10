defmodule UnicodeSecurity.InvalidInputError do
  @moduledoc """
  Raised when input exceeds 4096 bytes or contains invalid UTF-8.

  `reason` is `:invalid_utf8` or `:input_too_long`. `byte_offset` is zero-based:
  it identifies the start of the first malformed UTF-8 sequence, or 4096 for
  oversized input. The size limit is checked before decoding.
  """

  defexception [:reason, :byte_offset]

  @type t :: %__MODULE__{
          reason: :invalid_utf8 | :input_too_long,
          byte_offset: non_neg_integer()
        }

  @impl true
  def message(%__MODULE__{reason: :invalid_utf8, byte_offset: offset}),
    do: "invalid UTF-8 at byte offset #{offset}"

  def message(%__MODULE__{reason: :input_too_long}), do: "input exceeds 4096 bytes"
end
