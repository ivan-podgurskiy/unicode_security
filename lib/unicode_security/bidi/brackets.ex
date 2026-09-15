defmodule UnicodeSecurity.Bidi.Brackets do
  @moduledoc false

  alias UnicodeSecurity.Data.Bidi, as: Data

  @spec resolve([map()], :l | :r, :l | :r) :: [map()]
  def resolve(chars, embedding, sos) do
    indexed = chars |> Enum.with_index() |> Map.new(fn {char, index} -> {index, char} end)
    pairs = chars |> find_pairs(0, [], []) |> Map.new()

    # Visit opening positions in logical order without an input-sized sort.
    resolved =
      Enum.reduce(0..(length(chars) - 1), indexed, fn opening, acc ->
        case Map.fetch(pairs, opening) do
          {:ok, closing} -> resolve_pair({opening, closing}, acc, embedding, sos)
          :error -> acc
        end
      end)

    for index <- 0..(length(chars) - 1), do: Map.fetch!(resolved, index)
  end

  # BD14–BD16: a bounded stack, canonical bracket equivalence, and the required
  # all-pairs cancellation on overflow. Overrides can disable bracket pairing.
  defp find_pairs([], _index, _stack, pairs), do: pairs

  defp find_pairs([char | rest], index, stack, pairs) do
    bracket = if char.type == :on, do: Data.bracket(char.code), else: nil

    case bracket do
      {_pair, :open} when length(stack) == 63 ->
        []

      {pair, :open} ->
        find_pairs(rest, index + 1, [{canonical(pair), index} | stack], pairs)

      {_pair, :close} ->
        {stack, pairs} = close_bracket(char.code, index, stack, pairs)
        find_pairs(rest, index + 1, stack, pairs)

      nil ->
        find_pairs(rest, index + 1, stack, pairs)
    end
  end

  defp close_bracket(code, index, stack, pairs) do
    case Enum.drop_while(stack, fn {pair, _opening} -> pair != canonical(code) end) do
      [] -> {stack, pairs}
      [{_pair, opening} | tail] -> {tail, [{opening, index} | pairs]}
    end
  end

  # UAX #9 guarantees that these are the only canonical-equivalent bracket pairs.
  defp canonical(0x232A), do: 0x3009
  defp canonical(code), do: code

  defp resolve_pair({opening, closing}, chars, embedding, sos) do
    enclosed = enclosed_direction(chars, opening + 1, closing, embedding, nil)

    direction =
      case enclosed do
        nil -> nil
        ^embedding -> embedding
        _opposite -> preceding_direction(chars, opening - 1, sos)
      end

    if direction do
      chars
      |> set_bracket(opening, direction)
      |> set_bracket(closing, direction)
    else
      chars
    end
  end

  # No repeated list indexing: bracket nesting is bounded at 63, so the total
  # enclosed scan is bounded by 63 visits per position (plus map lookup costs).
  defp enclosed_direction(_chars, index, closing, _embedding, found) when index == closing,
    do: found

  defp enclosed_direction(chars, index, closing, embedding, found) do
    strong = strong_type(Map.fetch!(chars, index).type)

    if strong == embedding do
      strong
    else
      enclosed_direction(chars, index + 1, closing, embedding, strong || found)
    end
  end

  defp preceding_direction(_chars, index, sos) when index < 0, do: sos

  defp preceding_direction(chars, index, sos) do
    strong_type(Map.fetch!(chars, index).type) || preceding_direction(chars, index - 1, sos)
  end

  defp strong_type(type) when type in [:en, :an, :r], do: :r
  defp strong_type(:l), do: :l
  defp strong_type(_type), do: nil

  defp set_bracket(chars, index, direction) do
    chars = Map.update!(chars, index, &%{&1 | type: direction})
    following_marks(chars, index + 1, direction)
  end

  # N0 also updates every immediately following character originally of type NSM.
  defp following_marks(chars, index, direction) do
    case Map.get(chars, index) do
      %{original: :nsm} = char ->
        following_marks(Map.put(chars, index, %{char | type: direction}), index + 1, direction)

      _ ->
        chars
    end
  end
end
