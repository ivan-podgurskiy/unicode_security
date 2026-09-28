defmodule UnicodeSecurity.InvalidDomainError do
  @moduledoc "Raised when an original UTF-8 input fails domain validity checks."
  defexception [:reason, :byte_offset, :label_index]

  @impl true
  def message(_error), do: "Input is not a valid domain name"
end
