defmodule UnicodeSecurity.Bidi do
  @moduledoc false

  # UTS #39 revision 34 uses the UAX #9 revision 51 algorithm with Unicode 18
  # properties. P1 separates B-delimited paragraphs; each is one line, with no
  # layout width or wrapping protocol. U+2028 retains its WS behavior. The
  # conformance boundary exposes L2 results; reorder/1 adds mandatory L3 and L4.

  alias UnicodeSecurity.Bidi.Brackets
  alias UnicodeSecurity.Bidi.Explicit
  alias UnicodeSecurity.Bidi.Weak
  alias UnicodeSecurity.Data.Bidi, as: Data

  @isolates [:lri, :rli, :fsi]
  @neutrals [:b, :s, :ws, :on, :lri, :rli, :fsi, :pdi]
  @whitespace [:ws, :lri, :rli, :fsi, :pdi]

  @spec reorder([0..0x10FFFF]) :: [0..0x10FFFF]
  def reorder(scalars) do
    # Printable ASCII cannot change bidi order or contain X9 removals. Other
    # inputs take the complete algorithm, including controls and Arabic numbers.
    if Enum.all?(scalars, &(&1 in 0x20..0x7E)) do
      scalars
    else
      scalars
      |> paragraphs()
      |> Enum.flat_map(&visual_paragraph/1)
    end
  end

  defp paragraphs(scalars) do
    Enum.chunk_while(
      scalars,
      [],
      fn code, reversed ->
        if Data.class(code) == :b,
          do: {:cont, Enum.reverse([code | reversed]), []},
          else: {:cont, [code | reversed]}
      end,
      fn
        [] -> {:cont, []}
        reversed -> {:cont, Enum.reverse(reversed), []}
      end
    )
  end

  defp visual_paragraph(paragraph) do
    {_logical, visual, _level} = resolve_paragraph(paragraph, 0)

    visual
    |> Enum.chunk_by(& &1.level)
    |> Enum.flat_map(&place_marks/1)
    |> Enum.map(fn char ->
      if rem(char.level, 2) == 1, do: Data.mirror(char.code), else: char.code
    end)
  end

  # Internal conformance boundary: one paragraph, one line, through L2. The
  # public skeleton always passes level 0; :auto/1 also exercise P2/P3 and X5c.
  @spec resolve([0..0x10FFFF], 0 | 1 | :auto) :: map()
  def resolve(scalars, direction) do
    {logical, visual, paragraph} = resolve_paragraph(scalars, direction)
    levels = Map.new(logical, &{&1.index, &1.level})

    input_levels =
      scalars
      |> Enum.with_index()
      |> Enum.map(fn {_code, index} -> Map.get(levels, index, :x) end)

    %{levels: input_levels, order: Enum.map(visual, & &1.index), paragraph_level: paragraph}
  end

  defp resolve_paragraph(scalars, direction) do
    chars =
      scalars
      |> Enum.with_index()
      |> Enum.map(fn {code, index} ->
        type = Data.class(code)
        %{code: code, index: index, original: type, type: type, level: 0}
      end)

    {active, matching, paragraph} = Explicit.resolve(chars, direction)

    by_index =
      active
      |> sequences(matching, paragraph)
      |> Enum.flat_map(fn {sequence, sos, eos} ->
        embedding = direction(hd(sequence).level)

        sequence
        |> Weak.resolve(sos)
        |> Brackets.resolve(embedding, sos)
        |> neutrals(sos, eos, embedding)
        |> Enum.map(&implicit_level/1)
      end)
      |> Map.new(&{&1.index, &1})

    resolved =
      active
      |> Enum.map(&Map.fetch!(by_index, &1.index))
      |> reset_whitespace(paragraph)

    {resolved, reorder_levels(resolved), paragraph}
  end

  # X10: preserve explicit neighboring levels before any implicit adjustments.
  defp sequences([], _matching, _paragraph), do: []

  defp sequences(chars, matching, paragraph) do
    {with_previous, _} =
      Enum.map_reduce(chars, paragraph, fn char, previous ->
        {Map.put(char, :previous, previous), char.level}
      end)

    {with_next, _} =
      with_previous
      |> Enum.reverse()
      |> Enum.map_reduce(paragraph, fn char, next ->
        {Map.put(char, :next, next), char.level}
      end)

    runs = with_next |> Enum.reverse() |> Enum.chunk_by(& &1.level) |> Enum.with_index()
    by_id = Map.new(runs, fn {run, id} -> {id, run} end)
    starts = Map.new(runs, fn {run, id} -> {hd(run).index, id} end)

    links =
      Map.new(runs, fn {run, id} ->
        last = List.last(run)

        next =
          if last.original in @isolates do
            Map.get(starts, Map.get(matching, last.index))
          end

        {id, next}
      end)

    incoming = links |> Map.values() |> MapSet.new()

    for {_run, id} <- runs, not MapSet.member?(incoming, id) do
      sequence = collect_runs(id, by_id, links)
      first = hd(sequence)
      last = List.last(sequence)
      following = if last.original in @isolates, do: paragraph, else: last.next

      {sequence, direction(max(first.level, first.previous)),
       direction(max(last.level, following))}
    end
  end

  defp collect_runs(nil, _runs, _links), do: []

  defp collect_runs(id, runs, links),
    do: Map.fetch!(runs, id) ++ collect_runs(Map.fetch!(links, id), runs, links)

  # N1/N2. European and Arabic numbers supply strong R context.
  defp neutrals([], _previous, _eos, _embedding), do: []

  defp neutrals([%{type: type} | _] = chars, previous, eos, embedding) when type in @neutrals do
    {run, rest} = Enum.split_while(chars, &(&1.type in @neutrals))

    next =
      case rest do
        [] -> eos
        [char | _] -> strong_direction(char.type)
      end

    resolved = if previous == next, do: previous, else: embedding
    Enum.map(run, &%{&1 | type: resolved}) ++ neutrals(rest, resolved, eos, embedding)
  end

  defp neutrals([char | rest], _previous, eos, embedding),
    do: [char | neutrals(rest, strong_direction(char.type), eos, embedding)]

  defp strong_direction(type) when type in [:en, :an], do: :r
  defp strong_direction(type), do: type

  # I1/I2: explicit levels do not exceed 125; implicit levels may reach 126.
  defp implicit_level(char) do
    increment =
      case {rem(char.level, 2), char.type} do
        {0, :r} -> 1
        {0, type} when type in [:an, :en] -> 2
        {1, type} when type != :r -> 1
        _ -> 0
      end

    %{char | level: char.level + increment}
  end

  defp reset_whitespace(chars, paragraph) do
    {reversed, _reset} =
      chars
      |> Enum.reverse()
      |> Enum.map_reduce(true, fn char, reset ->
        cond do
          char.original in [:b, :s] -> {%{char | level: paragraph}, true}
          char.original in @whitespace and reset -> {%{char | level: paragraph}, true}
          true -> {char, false}
        end
      end)

    Enum.reverse(reversed)
  end

  defp reorder_levels([]), do: []

  defp reorder_levels(chars) do
    {minimum, maximum} = chars |> Enum.map(& &1.level) |> Enum.min_max()
    lowest_odd = if rem(minimum, 2) == 0, do: minimum + 1, else: minimum

    if lowest_odd > maximum do
      chars
    else
      Enum.reduce(maximum..lowest_odd//-1, chars, &reverse_level/2)
    end
  end

  defp reverse_level(level, chars) do
    chars
    |> Enum.chunk_by(&(&1.level >= level))
    |> Enum.flat_map(fn run ->
      if hd(run).level >= level, do: Enum.reverse(run), else: run
    end)
  end

  # L3 restores the logical order of a base and its following Mn/Me marks when
  # L2 reversed their odd-level run. Initial marks without a base stay in place.
  defp place_marks([%{level: level} | _] = chars) when rem(level, 2) == 0, do: chars
  defp place_marks(chars), do: place_marks(chars, [], [])
  defp place_marks([], marks, result), do: Enum.reverse(result) ++ Enum.reverse(marks)

  defp place_marks([char | rest], marks, result) do
    if Data.nonspacing_mark?(char.code) do
      place_marks(rest, [char | marks], result)
    else
      place_marks(rest, [], Enum.reverse([char | marks], result))
    end
  end

  defp direction(level) when rem(level, 2) == 0, do: :l
  defp direction(_level), do: :r
end
