defmodule UnicodeSecurity.Bidi.Explicit do
  @moduledoc false

  @isolates [:lri, :rli, :fsi]
  @removed [:rle, :lre, :rlo, :lro, :pdf, :bn]

  @spec resolve([map()], 0 | 1 | :auto) :: {[map()], map(), 0 | 1}
  def resolve(chars, direction) do
    {matching, directions, first_strong} = isolate_context(chars, [{nil, nil}], %{}, %{})
    paragraph = if direction == :auto, do: first_strong, else: direction

    state = %{
      stack: [{paragraph, :neutral, false}],
      overflow_isolates: 0,
      overflow_embeddings: 0,
      valid_isolates: 0
    }

    {resolved, _state} =
      Enum.map_reduce(chars, state, &resolve_char(&1, &2, directions, paragraph))

    {Enum.reject(resolved, &(&1.original in @removed)), matching, paragraph}
  end

  # BD8–BD13 and P2/P3, including X5c's independent first-strong calculation.
  # Each character is visited once, even in deeply nested/overflowing isolates.
  defp isolate_context([], stack, matching, directions) do
    directions =
      Enum.reduce(stack, directions, fn {index, strong}, acc ->
        Map.put(acc, index, direction(strong))
      end)

    {matching, directions, Map.fetch!(directions, nil)}
  end

  defp isolate_context([char | rest], stack, matching, directions) do
    case {char.original, stack} do
      {type, _} when type in @isolates ->
        isolate_context(rest, [{char.index, nil} | stack], matching, directions)

      {:pdi, [{opening, strong}, next | tail]} ->
        isolate_context(
          rest,
          [next | tail],
          Map.put(matching, opening, char.index),
          Map.put(directions, opening, direction(strong))
        )

      {type, [{index, nil} | tail]} when type in [:l, :r, :al] ->
        isolate_context(rest, [{index, type} | tail], matching, directions)

      _ ->
        isolate_context(rest, stack, matching, directions)
    end
  end

  defp direction(type) when type in [:r, :al], do: 1
  defp direction(_type), do: 0

  defp resolve_char(char, state, directions, paragraph) do
    {level, override, _isolate} = hd(state.stack)

    case char.original do
      type when type in [:rle, :lre, :rlo, :lro] ->
        {char, embedding(state, type)}

      type when type in @isolates ->
        target = isolate_direction(type, char.index, directions)
        {assign(char, level, override), isolate(state, target)}

      :pdi ->
        state = pop_isolate(state)
        {new_level, new_override, _} = hd(state.stack)
        {assign(char, new_level, new_override), state}

      :pdf ->
        {char, pop_embedding(state)}

      :b ->
        {%{char | level: paragraph}, state}

      :bn ->
        {char, state}

      _ ->
        {assign(char, level, override), state}
    end
  end

  defp isolate_direction(:lri, _index, _directions), do: 0
  defp isolate_direction(:rli, _index, _directions), do: 1
  defp isolate_direction(:fsi, index, directions), do: Map.fetch!(directions, index)

  defp assign(char, level, :neutral), do: %{char | level: level}
  defp assign(char, level, override), do: %{char | level: level, type: override}

  # X2–X5. The explicit depth is bounded by 125, regardless of input length.
  defp embedding(state, type) do
    {level, _override, _isolate} = hd(state.stack)
    target = if type in [:rle, :rlo], do: 1, else: 0
    new_level = next_level(level, target)

    cond do
      new_level <= 125 and state.overflow_isolates == 0 and state.overflow_embeddings == 0 ->
        %{state | stack: [{new_level, override(type), false} | state.stack]}

      state.overflow_isolates == 0 ->
        %{state | overflow_embeddings: state.overflow_embeddings + 1}

      true ->
        state
    end
  end

  defp override(:rlo), do: :r
  defp override(:lro), do: :l
  defp override(_embedding), do: :neutral

  defp isolate(state, target) do
    {level, _override, _isolate} = hd(state.stack)
    new_level = next_level(level, target)

    if new_level <= 125 and state.overflow_isolates == 0 and state.overflow_embeddings == 0 do
      %{
        state
        | stack: [{new_level, :neutral, true} | state.stack],
          valid_isolates: state.valid_isolates + 1
      }
    else
      %{state | overflow_isolates: state.overflow_isolates + 1}
    end
  end

  defp next_level(level, target), do: level + 1 + if(rem(level, 2) == target, do: 1, else: 0)

  # X6a and X7 distinguish valid scopes from both kinds of overflow.
  defp pop_isolate(%{overflow_isolates: count} = state) when count > 0,
    do: %{state | overflow_isolates: count - 1}

  defp pop_isolate(%{valid_isolates: 0} = state), do: state

  defp pop_isolate(state) do
    [_isolate | rest] =
      Enum.drop_while(state.stack, fn {_level, _override, isolate} -> not isolate end)

    %{state | stack: rest, valid_isolates: state.valid_isolates - 1, overflow_embeddings: 0}
  end

  defp pop_embedding(%{overflow_isolates: count} = state) when count > 0, do: state

  defp pop_embedding(%{overflow_embeddings: count} = state) when count > 0,
    do: %{state | overflow_embeddings: count - 1}

  defp pop_embedding(%{stack: [{_level, _override, false}, next | tail]} = state),
    do: %{state | stack: [next | tail]}

  defp pop_embedding(state), do: state
end
