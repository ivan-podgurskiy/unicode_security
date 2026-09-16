defmodule UnicodeSecurity.UnicodeData.IdentifierGenerator do
  @moduledoc false

  alias UnicodeSecurity.UnicodeData.Packer

  @spec render!([tuple()], [tuple()], map(), [tuple()]) :: binary()
  def render!(statuses, types, decompositions, combining_ranges) do
    combining_classes = combining_class_map(combining_ranges)

    allowed =
      statuses
      |> Enum.filter(&(elem(&1, 2) == :allowed))
      |> Enum.flat_map(fn {first, last, _status} -> Enum.to_list(first..last) end)
      |> MapSet.new()

    validate_hangul_profile!(allowed, decompositions, combining_classes)

    {rescue_index, rescue_values} =
      allowed
      |> Enum.sort()
      |> Enum.reject(&hangul_syllable?/1)
      |> Enum.map(&generator_nfd(&1, decompositions, combining_classes))
      |> Enum.filter(fn decomposition ->
        Enum.any?(decomposition, &(not MapSet.member?(allowed, &1)))
      end)
      |> Enum.uniq()
      |> Enum.sort()
      |> validate_rescues!(combining_classes)
      |> pack_rescues()

    status_indices = %{restricted: 0, allowed: 1}

    type_sets =
      [[:not_character] | types |> Enum.map(&elem(&1, 2)) |> Enum.uniq() |> Enum.sort()]
      |> Enum.uniq()

    type_indices = type_sets |> Enum.with_index() |> Map.new()
    packed_statuses = indexed_ranges(statuses, status_indices)
    packed_types = indexed_ranges(types, type_indices)

    render_identifier(type_sets, packed_statuses, packed_types, rescue_index, rescue_values)
  end

  defp indexed_ranges(records, indices) do
    records
    |> Enum.map(fn {first, last, value} -> {first, last, Map.fetch!(indices, value)} end)
    |> Packer.ranges()
  end

  defp render_identifier(type_sets, statuses, types, rescue_index, rescue_values) do
    # Values have been mapped to this closed set by IdentifierParser. Emit only
    # literal atoms; never intern source-derived strings in generated/runtime code.
    sets_literal =
      Enum.map_join(type_sets, ",", fn set ->
        "[" <> Enum.map_join(set, ",", &(":" <> Atom.to_string(&1))) <> "]"
      end)

    source = """
    defmodule UnicodeSecurity.Data.Identifier do
      @moduledoc false

      @statuses Base.decode64!(#{encoded_literal(statuses)})
      @types Base.decode64!(#{encoded_literal(types)})
      @rescue_index Base.decode64!(#{encoded_literal(rescue_index)})
      @rescue_values Base.decode64!(#{encoded_literal(rescue_values)})
      @sets {#{sets_literal}}

      @spec status(non_neg_integer()) :: :allowed | :restricted
      def status(code), do: if(range(@statuses, code) == 1, do: :allowed, else: :restricted)

      @spec types(non_neg_integer()) :: [atom()]
      def types(code), do: elem(@sets, range(@types, code))

      @spec rescues(non_neg_integer()) :: [[non_neg_integer()]]
      def rescues(code), do: rescues(@rescue_index, @rescue_values, code, 0, div(byte_size(@rescue_index), 10) - 1)

      defp rescues(_index, _values, _code, low, high) when low > high, do: []

      defp rescues(index, values, code, low, high) do
        middle = div(low + high, 2)
        <<matched::32, offset::32, count::16>> = :binary.part(index, middle * 10, 10)

        cond do
          code < matched -> rescues(index, values, code, low, middle - 1)
          code > matched -> rescues(index, values, code, middle + 1, high)
          true -> unpack_rescues(values, offset, count, [])
        end
      end

      defp unpack_rescues(_values, _offset, 0, acc), do: Enum.reverse(acc)

      defp unpack_rescues(values, offset, count, acc) do
        <<length::8>> = :binary.part(values, offset, 1)
        bytes = length * 4
        mapping = for <<scalar::32 <- :binary.part(values, offset + 1, bytes)>>, do: scalar
        unpack_rescues(values, offset + 1 + bytes, count - 1, [mapping | acc])
      end

      defp range(table, code), do: range(table, code, 0, div(byte_size(table), 10) - 1)
      defp range(_table, _code, low, high) when low > high, do: 0

      defp range(table, code, low, high) do
        middle = div(low + high, 2)
        <<first::32, last::32, value::16>> = :binary.part(table, middle * 10, 10)

        cond do
          code < first -> range(table, code, low, middle - 1)
          code > last -> range(table, code, middle + 1, high)
          true -> value
        end
      end
    end
    """

    source |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
  end

  defp combining_class_map(ranges) do
    Map.new(
      for {first, last, value} <- ranges,
          value != 0,
          code <- first..last,
          do: {code, value}
    )
  end

  defp generator_nfd(code, decompositions, combining_classes) do
    code
    |> generator_decompose(decompositions)
    |> generator_reorder(combining_classes, [], [])
  end

  defp generator_decompose(code, _decompositions) when code in 0xAC00..0xD7A3 do
    index = code - 0xAC00
    leading = 0x1100 + div(index, 588)
    vowel = 0x1161 + div(rem(index, 588), 28)

    case rem(index, 28) do
      0 -> [leading, vowel]
      trailing -> [leading, vowel, 0x11A7 + trailing]
    end
  end

  defp generator_decompose(code, decompositions) do
    case Map.get(decompositions, code) do
      nil -> [code]
      mapping -> Enum.flat_map(mapping, &generator_decompose(&1, decompositions))
    end
  end

  defp generator_reorder([], _classes, marks, acc),
    do: Enum.reverse(generator_flush_marks(marks, acc))

  defp generator_reorder([code | rest], classes, marks, acc) do
    case Map.get(classes, code, 0) do
      0 -> generator_reorder(rest, classes, [], [code | generator_flush_marks(marks, acc)])
      class -> generator_reorder(rest, classes, [{code, class} | marks], acc)
    end
  end

  defp generator_flush_marks(marks, acc) do
    marks
    |> Enum.reverse()
    |> Enum.sort_by(&elem(&1, 1))
    |> Enum.reduce(acc, fn {code, _class}, result -> [code | result] end)
  end

  defp validate_hangul_profile!(allowed, decompositions, combining_classes) do
    Enum.each(0xAC00..0xD7A3, fn code ->
      unless MapSet.member?(allowed, code) and
               generator_nfd(code, decompositions, combining_classes) ==
                 hangul_decomposition(code) do
        raise ArgumentError, "unsupported Hangul identifier profile at U+#{hex(code)}"
      end
    end)
  end

  defp hangul_decomposition(code) do
    index = code - 0xAC00
    decomposition = [0x1100 + div(index, 588), 0x1161 + div(rem(index, 588), 28)]

    case rem(index, 28) do
      0 -> decomposition
      trailing -> decomposition ++ [0x11A7 + trailing]
    end
  end

  defp hangul_syllable?(code), do: code in 0xAC00..0xD7A3

  defp validate_rescues!(rescues, combining_classes) do
    Enum.each(rescues, fn mapping ->
      classes = Enum.map(mapping, &Map.get(combining_classes, &1, 0))

      unless length(mapping) in 2..255 and hd(classes) == 0 and
               (Enum.all?(tl(classes), &(&1 > 0)) or classes in [[0, 0], [0, 0, 0]]) do
        raise ArgumentError, "unsupported identifier rescue CCC shape: #{inspect(classes)}"
      end
    end)

    groups = Enum.group_by(rescues, &hd/1)

    if Enum.any?(groups, fn {_starter, candidates} -> length(candidates) > 8 end) do
      raise ArgumentError, "identifier rescue candidates exceed runtime bound"
    end

    groups
  end

  defp pack_rescues(groups) do
    groups
    |> Enum.sort()
    |> Enum.reduce({[], [], 0}, fn {starter, candidates}, {index, values, offset} ->
      encoded =
        Enum.map(candidates, fn candidate ->
          [<<length(candidate)::8>>, Enum.map(candidate, &<<&1::32>>)]
        end)
        |> IO.iodata_to_binary()

      record = Packer.mapping_index!(starter, offset, length(candidates))
      {[record | index], [encoded | values], offset + byte_size(encoded)}
    end)
    |> then(fn {index, values, _offset} ->
      {index |> Enum.reverse() |> IO.iodata_to_binary(),
       values |> Enum.reverse() |> IO.iodata_to_binary()}
    end)
  end

  defp hex(code), do: code |> Integer.to_string(16) |> String.upcase()

  defp encoded_literal(binary) do
    binary
    |> Base.encode64()
    |> inspect(limit: :infinity, printable_limit: :infinity)
  end
end
