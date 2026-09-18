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
  @spec nfc_scalars([0..0x10FFFF]) :: [0..0x10FFFF]
  def nfc_scalars(scalars), do: scalars |> nfd_scalars() |> recompose(nil, [], 0, [])

  # Keep the starter separately so composing across intervening marks is linear.
  defp recompose([], nil, _marks, _class, acc), do: Enum.reverse(acc)
  defp recompose([], starter, marks, _class, acc), do: Enum.reverse(marks ++ [starter | acc])

  defp recompose([scalar | rest], starter, marks, previous_class, acc) do
    class = Data.combining_class(scalar)

    composite =
      if starter != nil and (previous_class == 0 or previous_class < class),
        do: compose(starter, scalar)

    cond do
      composite != nil ->
        recompose(rest, composite, marks, previous_class, acc)

      class == 0 ->
        flushed = if starter == nil, do: acc, else: marks ++ [starter | acc]
        recompose(rest, scalar, [], 0, flushed)

      starter == nil ->
        recompose(rest, nil, [], class, [scalar | acc])

      true ->
        recompose(rest, starter, [scalar | marks], class, acc)
    end
  end

  defp compose(leading, vowel) when leading in 0x1100..0x1112 and vowel in 0x1161..0x1175,
    do: @s_base + ((leading - @l_base) * @v_count + vowel - @v_base) * @t_count

  defp compose(syllable, trailing)
       when syllable in 0xAC00..0xD7A3 and rem(syllable - @s_base, @t_count) == 0 and
              trailing in 0x11A8..0x11C2,
       do: syllable + trailing - @t_base

  defp compose(first, second), do: Composition.compose(first, second)

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

  defp reorder([scalar | rest], marks, acc) do
    case Data.combining_class(scalar) do
      0 -> reorder(rest, [], [scalar | flush_marks(marks, acc)])
      class -> reorder(rest, [{scalar, class} | marks], acc)
    end
  end

  defp flush_marks(marks, acc) do
    # Restore source order before the stable sort so equal classes keep their order.
    marks
    |> Enum.reverse()
    |> Enum.sort_by(fn {_scalar, class} -> class end)
    |> Enum.reduce(acc, fn {scalar, _class}, result -> [scalar | result] end)
  end
end
