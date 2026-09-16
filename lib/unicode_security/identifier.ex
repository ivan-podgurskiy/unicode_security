defmodule UnicodeSecurity.Identifier do
  @moduledoc false

  alias UnicodeSecurity.Data.Identifier, as: Data
  alias UnicodeSecurity.Data.Normalization, as: NormalizationData
  alias UnicodeSecurity.Normalization
  alias UnicodeSecurity.Utf8

  @l_base 0x1100
  @l_count 19
  @v_base 0x1161
  @v_count 21
  @t_base 0x11A7
  @t_count 28
  @s_base 0xAC00
  @n_count @v_count * @t_count

  @spec status(integer()) :: :allowed | :restricted
  def status(code) do
    scalar!(code)
    Data.status(code)
  end

  @spec types(integer()) :: [atom()]
  def types(code) do
    scalar!(code)
    Data.types(code)
  end

  @spec allowed?(binary()) :: boolean()
  def allowed?(input) do
    input
    |> Utf8.decode!()
    |> Enum.map(&elem(&1, 0))
    |> allowed_scalars?()
  end

  @doc false
  # Internal entry point for callers that already validated/decoded the original input.
  @spec allowed_scalars?([non_neg_integer()]) :: boolean()
  def allowed_scalars?(scalars) do
    {leading, segments} =
      scalars
      |> Normalization.nfd_scalars()
      |> segments()

    Enum.all?(leading, &allowed_scalar?/1) and suffix_allowed?(segments)
  end

  defp segments(scalars), do: segments(scalars, [], [], nil)

  defp segments([], leading, segments, nil),
    do: {Enum.reverse(leading), segments |> Enum.reverse() |> List.to_tuple()}

  defp segments([], leading, segments, {starter, marks}) do
    finished = {starter, Enum.reverse(marks)}
    {Enum.reverse(leading), [finished | segments] |> Enum.reverse() |> List.to_tuple()}
  end

  defp segments([code | rest], leading, segments, current) do
    if combining_class(code) == 0 do
      case current do
        nil ->
          segments(rest, leading, segments, {code, []})

        {starter, marks} ->
          segments(rest, leading, [{starter, Enum.reverse(marks)} | segments], {code, []})
      end
    else
      case current do
        nil -> segments(rest, [code | leading], segments, nil)
        {starter, marks} -> segments(rest, leading, segments, {starter, [code | marks]})
      end
    end
  end

  defp suffix_allowed?(segments) when tuple_size(segments) == 0, do: true

  defp suffix_allowed?(segments) do
    # All transitions consume at most three segments. The suffix list gives constant
    # lookahead without repeatedly copying a Boolean tuple; segments are tuple-indexed.
    suffix_allowed?(tuple_size(segments) - 1, segments, [true])
  end

  defp suffix_allowed?(-1, _segments, [result | _suffix]), do: result

  defp suffix_allowed?(index, segments, suffix) do
    accepted = transition?(index, segments, suffix)
    suffix_allowed?(index - 1, segments, [accepted | suffix])
  end

  defp transition?(index, segments, suffix) do
    {starter, marks} = elem(segments, index)

    (allowed_scalar?(starter) and Enum.all?(marks, &allowed_scalar?/1) and accepted?(suffix, 1)) or
      Enum.any?(Data.rescues(starter), &rescue_transition?(&1, index, segments, suffix)) or
      hangul_transition?(index, segments, suffix)
  end

  defp rescue_transition?([starter | candidate_marks], index, segments, suffix) do
    if combining_class(hd(candidate_marks)) > 0 do
      {^starter, input_marks} = elem(segments, index)
      marks_match?(candidate_marks, input_marks) and accepted?(suffix, 1)
    else
      starters_match?([starter | candidate_marks], index, segments) and
        accepted?(suffix, length(candidate_marks) + 1)
    end
  end

  defp starters_match?(candidate, index, segments) do
    count = length(candidate)

    index + count <= tuple_size(segments) and
      candidate
      |> Enum.with_index()
      |> Enum.all?(fn {starter, offset} ->
        {input_starter, marks} = elem(segments, index + offset)

        starter == input_starter and (offset == count - 1 or marks == []) and
          (offset != count - 1 or Enum.all?(marks, &allowed_scalar?/1))
      end)
  end

  defp marks_match?(candidate, input) do
    # Canonical ordering may interleave different CCCs, but never equal-CCC marks.
    # Rescue marks must be each group's prefix; every leftover must be Allowed.
    match_groups(group_marks(candidate), group_marks(input))
  end

  defp match_groups([], input), do: all_groups_allowed?(input)
  defp match_groups(_candidate, []), do: false

  defp match_groups([{candidate_class, candidate_marks} | candidate], [
         {input_class, input_marks} | input
       ]) do
    cond do
      candidate_class < input_class ->
        false

      candidate_class > input_class ->
        Enum.all?(input_marks, &allowed_scalar?/1) and
          match_groups([{candidate_class, candidate_marks} | candidate], input)

      true ->
        case drop_prefix(input_marks, candidate_marks) do
          {:ok, leftover} ->
            Enum.all?(leftover, &allowed_scalar?/1) and match_groups(candidate, input)

          :error ->
            false
        end
    end
  end

  defp group_marks(marks) do
    marks
    |> Enum.chunk_by(&combining_class/1)
    |> Enum.map(fn [first | _rest] = group -> {combining_class(first), group} end)
  end

  defp all_groups_allowed?(groups) do
    Enum.all?(groups, fn {_class, marks} -> Enum.all?(marks, &allowed_scalar?/1) end)
  end

  defp drop_prefix(input, []), do: {:ok, input}
  defp drop_prefix([code | input], [code | prefix]), do: drop_prefix(input, prefix)
  defp drop_prefix(_input, _prefix), do: :error

  defp hangul_transition?(index, segments, suffix) do
    case hangul_pair(index, segments) do
      nil ->
        false

      {leading, vowel, vowel_marks} ->
        lv = @s_base + (leading - @l_base) * @n_count + (vowel - @v_base) * @t_count

        hangul_triple?(lv, index, segments, suffix) or
          (Enum.all?(vowel_marks, &allowed_scalar?/1) and allowed_scalar?(lv) and
             accepted?(suffix, 2))
    end
  end

  defp hangul_pair(index, segments) when index + 1 < tuple_size(segments) do
    {leading, leading_marks} = elem(segments, index)
    {vowel, vowel_marks} = elem(segments, index + 1)

    if leading in @l_base..(@l_base + @l_count - 1) and leading_marks == [] and
         vowel in @v_base..(@v_base + @v_count - 1) do
      {leading, vowel, vowel_marks}
    end
  end

  defp hangul_pair(_index, _segments), do: nil

  defp hangul_triple?(lv, index, segments, suffix) when index + 2 < tuple_size(segments) do
    {_vowel, vowel_marks} = elem(segments, index + 1)
    {trailing, trailing_marks} = elem(segments, index + 2)

    vowel_marks == [] and trailing in (@t_base + 1)..(@t_base + @t_count - 1) and
      Enum.all?(trailing_marks, &allowed_scalar?/1) and allowed_scalar?(lv + trailing - @t_base) and
      accepted?(suffix, 3)
  end

  defp hangul_triple?(_lv, _index, _segments, _suffix), do: false

  defp accepted?(suffix, consumed), do: Enum.at(suffix, consumed - 1, false)
  defp allowed_scalar?(code), do: Data.status(code) == :allowed
  defp combining_class(code), do: NormalizationData.combining_class(code)

  defp scalar!(code)
       when is_integer(code) and code in 0..0x10FFFF and code not in 0xD800..0xDFFF,
       do: :ok

  defp scalar!(code), do: raise(ArgumentError, "invalid Unicode scalar: #{inspect(code)}")
end
