defmodule UnicodeSecurity.Scripts do
  @moduledoc false

  alias UnicodeSecurity.Data.Scripts, as: Data
  alias UnicodeSecurity.Utf8

  @spec scripts(binary()) :: [atom()]
  def scripts(input) do
    input
    |> Utf8.decode!()
    |> Enum.map(fn {code, _offset} -> Data.script(code) end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  @spec mixed_script?(binary()) :: boolean()
  def mixed_script?(input) do
    input
    |> Utf8.decode!()
    |> Enum.map(&elem(&1, 0))
    |> resolved_set()
    |> empty?()
  end

  # UTS #39 revision 34, section 5.1. ALL is the intersection identity.
  @spec resolved_set([non_neg_integer()]) :: :all | MapSet.t(atom())
  def resolved_set(scalars) do
    Enum.reduce(scalars, :all, fn code, resolved ->
      intersect(resolved, augmented_set(code))
    end)
  end

  defp augmented_set(code) do
    extensions = Data.extensions(code)

    if :common in extensions or :inherited in extensions do
      :all
    else
      extensions |> Enum.flat_map(&augment/1) |> MapSet.new()
    end
  end

  defp augment(:han), do: [:han, :hanb, :hntl, :jpan, :kore]
  defp augment(:latin), do: [:latin, :hntl]
  defp augment(:hiragana), do: [:hiragana, :jpan]
  defp augment(:katakana), do: [:katakana, :jpan]
  defp augment(:hangul), do: [:hangul, :kore]
  defp augment(:bopomofo), do: [:bopomofo, :hanb]
  defp augment(script), do: [script]

  defp intersect(:all, set), do: set
  defp intersect(set, :all), do: set
  defp intersect(left, right), do: MapSet.intersection(left, right)

  defp empty?(:all), do: false
  defp empty?(set), do: MapSet.size(set) == 0
end
