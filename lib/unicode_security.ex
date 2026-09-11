defmodule UnicodeSecurity do
  @moduledoc """
  Unicode identifier security primitives backed by pinned Unicode data.

  A skeleton is a comparison key, not a canonical identifier or replacement value.
  """

  @doc """
  Returns the UTS #39 confusable skeleton using the pinned Unicode data.

  The result is a comparison key only; do not use it as a canonical identifier,
  display value, or replacement for the original input.

  Accepts a UTF-8 binary of at most 4,096 bytes. Raises `ArgumentError` for
  nonbinary input and `UnicodeSecurity.InvalidInputError` for malformed UTF-8
  or oversized input. The returned skeleton may exceed the input byte limit.
  """
  @spec skeleton(binary()) :: binary()
  defdelegate skeleton(input), to: UnicodeSecurity.Confusables
end
