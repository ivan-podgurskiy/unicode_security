defmodule UnicodeSecurity.Bidi.Weak do
  @moduledoc false

  @spec resolve([map()], :l | :r) :: [map()]
  def resolve(chars, sos) do
    chars
    |> nonspacing(sos)
    |> arabic_numbers(sos)
    |> separators(sos)
    |> terminators(sos)
    |> Enum.map(fn char ->
      if char.type in [:es, :et, :cs], do: %{char | type: :on}, else: char
    end)
    |> european_numbers(sos)
  end

  # W1: after an isolate formatting character an NSM becomes ON.
  defp nonspacing(chars, sos) do
    {chars, _last} =
      Enum.map_reduce(chars, sos, fn char, previous ->
        previous = if previous in [:lri, :rli, :fsi, :pdi], do: :on, else: previous
        type = if char.type == :nsm, do: previous, else: char.type
        {%{char | type: type}, type}
      end)

    chars
  end

  # W2 and W3, retaining AL as preceding-strong evidence before replacing it.
  defp arabic_numbers(chars, sos) do
    {chars, _last} =
      Enum.map_reduce(chars, sos, fn char, strong ->
        next = if char.type in [:l, :r, :al], do: char.type, else: strong

        type =
          cond do
            char.type == :en and strong == :al -> :an
            char.type == :al -> :r
            true -> char.type
          end

        {%{char | type: type}, next}
      end)

    chars
  end

  # W4 examines the neighbors' types before this pass.
  defp separators([], _previous), do: []

  defp separators([char | rest], previous) do
    next =
      case rest do
        [following | _] -> following.type
        [] -> :on
      end

    type = separator_type(char.type, previous, next)
    [%{char | type: type} | separators(rest, char.type)]
  end

  defp separator_type(:es, :en, :en), do: :en
  defp separator_type(:cs, type, type) when type in [:en, :an], do: type
  defp separator_type(type, _previous, _next), do: type

  # W5: consume each ET run once rather than repeatedly scanning its neighbors.
  defp terminators([], _previous), do: []

  defp terminators([%{type: :et} | _] = chars, previous) do
    {run, rest} = Enum.split_while(chars, &(&1.type == :et))
    next_en = match?([%{type: :en} | _], rest)
    type = if previous == :en or next_en, do: :en, else: :et
    Enum.map(run, &%{&1 | type: type}) ++ terminators(rest, type)
  end

  defp terminators([char | rest], _previous), do: [char | terminators(rest, char.type)]

  # W7 sees the R values produced by W3, not the original AL values.
  defp european_numbers(chars, sos) do
    {chars, _last} =
      Enum.map_reduce(chars, sos, fn char, strong ->
        next = if char.type in [:l, :r], do: char.type, else: strong
        type = if char.type == :en and strong == :l, do: :l, else: char.type
        {%{char | type: type}, next}
      end)

    chars
  end
end
