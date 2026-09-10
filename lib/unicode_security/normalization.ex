defmodule UnicodeSecurity.Normalization do
  @moduledoc false

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
    |> Enum.flat_map(fn {scalar, _offset} -> decompose(scalar) end)
    |> reorder([], [])
    |> Enum.map(fn scalar -> <<scalar::utf8>> end)
    |> IO.iodata_to_binary()
  end

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
