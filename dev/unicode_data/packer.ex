defmodule UnicodeSecurity.UnicodeData.Packer do
  @moduledoc false

  @maximum_offset 0xFFFFFFFF
  @maximum_count 0xFFFF

  @spec ranges([{non_neg_integer(), non_neg_integer(), non_neg_integer()}]) :: binary()
  def ranges(ranges) when is_list(ranges) do
    ranges
    |> validate_ranges!()
    |> Enum.map(fn {first, last, value} -> <<first::32, last::32, value::16>> end)
    |> IO.iodata_to_binary()
  end

  @spec mapping([{non_neg_integer(), [non_neg_integer()]}]) :: {binary(), binary()}
  def mapping(mappings) when is_list(mappings) do
    {index, values, _offset, _previous} =
      Enum.reduce(mappings, {[], [], 0, nil}, fn {codepoint, mapping},
                                                 {index, values, offset, previous} ->
        scalar!(codepoint)
        ordered_after!(codepoint, previous, :mapping)

        unless is_list(mapping) and mapping != [] do
          raise ArgumentError, "mapping for #{hex(codepoint)} must be a non-empty list"
        end

        count = length(mapping)
        index_record = mapping_index!(codepoint, offset, count)

        Enum.each(mapping, &scalar!/1)

        value_records = Enum.map(mapping, &<<&1::32>>)

        {[index_record | index], [value_records | values], offset + count, codepoint}
      end)

    {index |> Enum.reverse() |> IO.iodata_to_binary(),
     values |> Enum.reverse() |> IO.iodata_to_binary()}
  end

  @doc false
  @spec mapping_index!(non_neg_integer(), non_neg_integer(), pos_integer()) :: binary()
  def mapping_index!(codepoint, offset, count) do
    scalar!(codepoint)

    unless is_integer(offset) and offset in 0..@maximum_offset do
      raise ArgumentError, "mapping offset must fit in 32 bits"
    end

    unless is_integer(count) and count in 1..@maximum_count do
      raise ArgumentError, "mapping for #{hex(codepoint)} must contain 1 to 65,535 values"
    end

    <<codepoint::32, offset::32, count::16>>
  end

  defp validate_ranges!(ranges) do
    Enum.reduce(ranges, {[], nil}, fn {first, last, value} = range, {validated, previous_last} ->
      scalar!(first)
      scalar!(last)

      if first > last do
        raise ArgumentError, "descending packed range: #{hex(first)}..#{hex(last)}"
      end

      unless scalar_range?(first, last) do
        raise ArgumentError, "invalid Unicode scalar range: #{hex(first)}..#{hex(last)}"
      end

      ordered_after!(first, previous_last, :range)

      unless is_integer(value) and value in 0..@maximum_count do
        raise ArgumentError, "range value must fit in 16 bits: #{inspect(value)}"
      end

      {[range | validated], last}
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp ordered_after!(_current, nil, _kind), do: :ok

  defp ordered_after!(current, previous, kind) when current <= previous do
    raise ArgumentError, "#{kind} records must be sorted and non-overlapping"
  end

  defp ordered_after!(_current, _previous, _kind), do: :ok

  defp scalar!(codepoint)
       when is_integer(codepoint) and codepoint in 0..0x10FFFF and
              codepoint not in 0xD800..0xDFFF,
       do: :ok

  defp scalar!(codepoint),
    do: raise(ArgumentError, "invalid Unicode scalar: #{inspect(codepoint)}")

  defp scalar_range?(first, last) do
    first <= last and (last < 0xD800 or first > 0xDFFF)
  end

  defp hex(codepoint), do: codepoint |> Integer.to_string(16) |> String.upcase()
end
