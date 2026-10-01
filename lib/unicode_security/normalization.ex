defmodule UnicodeSecurity.Normalization do
  @moduledoc false

  alias UnicodeSecurity.Data.Composition
  alias UnicodeSecurity.Data.Normalization, as: Data
  alias UnicodeSecurity.Utf8

  @s_base 0xAC00
  @l_base 0x1100
  @v_base 0x1161
  @t_base 0x11A7
  @v_count 21
  @t_count 28
  @n_count @v_count * @t_count
  @s_count 19 * @n_count

  @spec nfd(binary()) :: binary()
  def nfd(input) do
    input
    |> Utf8.decode!()
    |> Enum.map(fn {scalar, _offset} -> scalar end)
    |> nfd_scalars()
    |> Enum.map(fn scalar -> <<scalar::utf8>> end)
    |> IO.iodata_to_binary()
  end

  # Internal pipeline entry point: callers supply already validated Unicode scalars.
  # Generated expansions are not subject to the original binary input byte limit.
  @doc false
  @spec nfd_scalars([0..0x10FFFF]) :: [0..0x10FFFF]
  def nfd_scalars(scalars) do
    # Every pinned ASCII scalar is undecomposable with CCC0, including controls.
    # This only skips canonical normalization; bidi/control/MA work stays intact.
    if Enum.all?(scalars, &(&1 <= 0x7F)) do
      scalars
    else
      scalars |> Enum.flat_map(&decompose/1) |> reorder([], [])
    end
  end

  @doc false
  @spec nfd_tagged([{0..0x10FFFF, non_neg_integer()}]) ::
          [{0..0x10FFFF, non_neg_integer()}]
  def nfd_tagged(values) do
    values
    |> Enum.flat_map(fn {scalar, origin} ->
      Enum.map(decompose(scalar), &{&1, origin})
    end)
    |> reorder([], [])
  end

  @doc false
  @spec nfc_scalars([0..0x10FFFF]) :: [0..0x10FFFF]
  def nfc_scalars(scalars), do: scalars |> nfd_scalars() |> recompose(nil, [], 0, [])

  @doc false
  @spec nfc_tagged([{0..0x10FFFF, non_neg_integer()}]) ::
          [{0..0x10FFFF, non_neg_integer()}]
  def nfc_tagged(values), do: values |> nfd_tagged() |> recompose(nil, [], 0, [])

  # Keep the starter separately so composing across intervening marks is linear.
  defp recompose([], nil, _marks, _class, acc), do: Enum.reverse(acc)
  defp recompose([], starter, marks, _class, acc), do: Enum.reverse(marks ++ [starter | acc])

  defp recompose([value | rest], starter, marks, previous_class, acc) do
    class = combining_class(scalar_value(value))

    composite =
      if starter != nil and (previous_class == 0 or previous_class < class),
        do: compose(scalar_value(starter), scalar_value(value))

    cond do
      composite != nil ->
        recompose(rest, composed_value(composite, starter, value), marks, previous_class, acc)

      class == 0 ->
        flushed = if starter == nil, do: acc, else: marks ++ [starter | acc]
        recompose(rest, value, [], 0, flushed)

      starter == nil ->
        recompose(rest, nil, [], class, [value | acc])

      true ->
        recompose(rest, starter, [value | marks], class, acc)
    end
  end

  defp composed_value(code, {_left, left_origin}, {_right, right_origin}),
    do: {code, min(left_origin, right_origin)}

  defp composed_value(code, _left, _right), do: code

  defp compose(leading, vowel) when leading in 0x1100..0x1112 and vowel in 0x1161..0x1175,
    do: @s_base + ((leading - @l_base) * @v_count + vowel - @v_base) * @t_count

  defp compose(syllable, trailing)
       when syllable in 0xAC00..0xD7A3 and rem(syllable - @s_base, @t_count) == 0 and
              trailing in 0x11A8..0x11C2,
       do: syllable + trailing - @t_base

  defp compose(first, second), do: Composition.compose(first, second)

  # The pinned normalization table has no ASCII decomposition or nonzero CCC.
  defp decompose(scalar) when scalar <= 0x7F, do: [scalar]

  defp decompose(scalar) when scalar >= @s_base and scalar < @s_base + @s_count do
    index = scalar - @s_base
    leading = @l_base + div(index, @n_count)
    vowel = @v_base + div(rem(index, @n_count), @t_count)

    case rem(index, @t_count) do
      0 -> [leading, vowel]
      trailing -> [leading, vowel, @t_base + trailing]
    end
  end

  defp decompose(scalar) do
    case Data.decomposition(scalar) do
      nil -> [scalar]
      mapping -> Enum.flat_map(mapping, &decompose/1)
    end
  end

  defp reorder([], marks, acc), do: Enum.reverse(flush_marks(marks, acc))

  defp reorder([value | rest], marks, acc) do
    case combining_class(scalar_value(value)) do
      0 -> reorder(rest, [], [value | flush_marks(marks, acc)])
      class -> reorder(rest, [{value, class} | marks], acc)
    end
  end

  defp scalar_value({scalar, _origin}), do: scalar
  defp scalar_value(scalar), do: scalar

  defp combining_class(scalar) when scalar <= 0x7F, do: 0
  defp combining_class(scalar), do: Data.combining_class(scalar)

  defp flush_marks(marks, acc) do
    # Restore source order before the stable sort so equal classes keep their order.
    marks
    |> Enum.reverse()
    |> Enum.sort_by(fn {_scalar, class} -> class end)
    |> Enum.reduce(acc, fn {scalar, _class}, result -> [scalar | result] end)
  end
end
