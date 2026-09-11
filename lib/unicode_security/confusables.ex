defmodule UnicodeSecurity.Confusables do
  @moduledoc false

  alias UnicodeSecurity.Data.Confusables, as: Data
  alias UnicodeSecurity.Normalization

  @spec skeleton(binary()) :: binary()
  def skeleton(input) do
    normalized = Normalization.nfd(input)

    normalized
    |> then(fn binary -> for <<scalar::utf8 <- binary>>, do: scalar end)
    |> Enum.flat_map(fn scalar -> Data.mapping(scalar) || [scalar] end)
    |> Normalization.nfd_scalars()
    |> Enum.map(fn scalar -> <<scalar::utf8>> end)
    |> IO.iodata_to_binary()
  end
end
