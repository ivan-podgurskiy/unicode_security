defmodule UnicodeSecurity.InvalidDomainError do
  @moduledoc """
  Raised by domain comparison and key APIs when an original input fails hostname validity.

  `reason` is a stable diagnostic code; the optional original byte offset and
  zero-based label index identify the selected earliest validity finding. The
  exception message is static and never incorporates untrusted input.
  """
  defexception [:reason, :byte_offset, :label_index]

  @impl true
  def message(_error), do: "Input is not a valid domain name"
end
