defmodule UnicodeSecurity.Confusables do
  @moduledoc false

  alias UnicodeSecurity.Bidi
  alias UnicodeSecurity.Data.Bidi, as: BidiData
  alias UnicodeSecurity.Data.Confusables, as: Data
  alias UnicodeSecurity.Normalization
  alias UnicodeSecurity.Utf8

  @spec skeleton(binary()) :: binary()
  def skeleton(input) do
    input
    |> Utf8.decode!()
    |> Enum.map(fn {scalar, _offset} -> scalar end)
    |> skeleton_scalars()
  end

  @doc false
  @spec skeleton_scalars([non_neg_integer()]) :: binary()
  def skeleton_scalars(scalars) do
    scalars
    |> Bidi.reorder()
    |> internal_skeleton()
    |> Enum.map(fn scalar -> <<scalar::utf8>> end)
    |> IO.iodata_to_binary()
  end

  # UTS #39 revision 34 internalSkeleton operates on already validated scalars;
  # only the original public input is checked against the byte limit.
  @doc false
  @spec internal_skeleton([0..0x10FFFF]) :: [0..0x10FFFF]
  def internal_skeleton(scalars) do
    scalars
    |> Normalization.nfd_scalars()
    |> Enum.reject(&BidiData.default_ignorable?/1)
    |> Enum.flat_map(fn scalar -> Data.mapping(scalar) || [scalar] end)
    |> Normalization.nfd_scalars()
  end
end
