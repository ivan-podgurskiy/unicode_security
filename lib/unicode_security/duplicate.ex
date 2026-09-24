defmodule UnicodeSecurity.Duplicate do
  @moduledoc """
  Occurrences of one exact binary input in an eager batch.

  Indexes are zero-based and preserve source enumeration order, including
  malformed or oversized binary inputs.
  """

  alias UnicodeSecurity.Reason

  defstruct [:input, :unicode_version, indexes: [], reasons: []]

  @type t :: %__MODULE__{
          input: binary() | nil,
          indexes: [non_neg_integer()],
          reasons: [Reason.t()],
          unicode_version: binary() | nil
        }
end
