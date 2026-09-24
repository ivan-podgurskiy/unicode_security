defmodule UnicodeSecurity.BatchItem do
  @moduledoc """
  One indexed audit input and its policy result.

  `input` is the unchanged source term. `index` is zero-based within each
  enumeration of an audit stream.
  """

  alias UnicodeSecurity.Result

  defstruct [:index, :input, :result]

  @type t :: %__MODULE__{
          index: non_neg_integer(),
          input: term(),
          result: Result.t()
        }
end
