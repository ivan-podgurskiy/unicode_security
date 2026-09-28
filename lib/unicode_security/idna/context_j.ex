defmodule UnicodeSecurity.Idna.ContextJ do
  @moduledoc false

  alias UnicodeSecurity.Data.Normalization
  alias UnicodeSecurity.Data.Profile

  @spec invalid_indexes([non_neg_integer()]) :: [non_neg_integer()]
  def invalid_indexes(scalars) do
    joining_types = Enum.map(scalars, &Profile.joining_type/1)

    right_neighbors =
      joining_types
      |> Enum.reverse()
      |> Enum.map_reduce(nil, fn type, nearest ->
        {nearest, if(type == :t, do: nearest, else: type)}
      end)
      |> elem(0)
      |> Enum.reverse()

    scalars
    |> Enum.zip(joining_types)
    |> Enum.zip(right_neighbors)
    |> Enum.with_index()
    |> Enum.reduce({nil, nil, []}, fn {{{scalar, type}, right}, index},
                                      {previous, left, invalid} ->
      valid =
        case scalar do
          0x200D -> virama?(previous)
          0x200C -> virama?(previous) or (left in [:l, :d] and right in [:r, :d])
          _ -> true
        end

      next_left = if type == :t, do: left, else: type
      {scalar, next_left, if(valid, do: invalid, else: [index | invalid])}
    end)
    |> elem(2)
    |> Enum.reverse()
  end

  defp virama?(nil), do: false
  defp virama?(scalar), do: Normalization.combining_class(scalar) == 9
end
