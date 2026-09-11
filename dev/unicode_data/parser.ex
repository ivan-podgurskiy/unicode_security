defmodule UnicodeSecurity.UnicodeData.Parser do
  @moduledoc false

  @type codepoint :: 0..0x10FFFF
  @type range_record :: {codepoint(), codepoint(), non_neg_integer()}

  @spec confusables!(binary()) :: %{codepoint() => [codepoint()]}
  def confusables!(input) when is_binary(input) do
    input
    |> data_lines()
    |> Enum.reduce(%{}, fn line, mappings ->
      case line |> String.split(";", trim: false) |> Enum.map(&String.trim/1) do
        [source, target, "MA"] when target != "" ->
          scalar = codepoint!(source, :confusables)
          mapping = target |> String.split() |> Enum.map(&codepoint!(&1, :confusables))

          if Map.has_key?(mappings, scalar) do
            raise ArgumentError, "duplicate confusable source: #{hex(scalar)}"
          end

          Map.put(mappings, scalar, mapping)

        _fields ->
          raise ArgumentError, "malformed MA confusable record: #{inspect(line)}"
      end
    end)
  end

  @spec unicode_data!(binary()) :: %{codepoint() => [codepoint()]}
  def unicode_data!(input) when is_binary(input) do
    input
    |> records!()
    |> validate_unicode_data_records!()
    |> Enum.reduce([], fn record, decompositions ->
      case canonical_decomposition!(record.decomposition) do
        nil -> decompositions
        mapping -> [{record.codepoint, mapping} | decompositions]
      end
    end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Map.new()
  end

  @spec ranges!(binary(), :integer) :: [range_record()]
  def ranges!(input, :integer) when is_binary(input) do
    input
    |> data_lines()
    |> Enum.map(&range_record!/1)
    |> Enum.sort_by(fn {first, last, _value} -> {first, last} end)
    |> reject_overlapping_ranges!()
    |> coalesce_ranges()
  end

  defp records!(input) do
    input
    |> data_lines()
    |> Enum.map(fn line ->
      case String.split(line, ";", trim: false) do
        [code, name, category, combining_class, bidi_class, decomposition | rest]
        when length(rest) == 9 ->
          %{
            codepoint: codepoint!(String.trim(code), :unicode_data),
            code: String.trim(code),
            name: name,
            category: category,
            decomposition: String.trim(decomposition),
            fields: [category, combining_class, bidi_class, decomposition | rest]
          }

        _fields ->
          raise ArgumentError, "malformed UnicodeData record: #{inspect(line)}"
      end
    end)
  end

  defp validate_unicode_data_records!(records) do
    duplicate =
      records
      |> Enum.frequencies_by(& &1.codepoint)
      |> Enum.find(fn {_codepoint, count} -> count > 1 end)

    if duplicate do
      {codepoint, _count} = duplicate
      raise ArgumentError, "duplicate UnicodeData code point: #{hex(codepoint)}"
    end

    validate_unicode_data_records!(records, [])
  end

  defp validate_unicode_data_records!([], validated), do: Enum.reverse(validated)

  defp validate_unicode_data_records!([first, last | rest], validated)
       when first.codepoint in 0xD800..0xDFFF do
    if surrogate_pair?(first, last) do
      validate_unicode_data_records!(rest, [last, first | validated])
    else
      raise ArgumentError, "unpaired UnicodeData surrogate range at #{first.code}"
    end
  end

  defp validate_unicode_data_records!([record | rest], validated) do
    if record.codepoint in 0xD800..0xDFFF do
      raise ArgumentError, "unpaired UnicodeData surrogate range at #{record.code}"
    end

    validate_unicode_data_records!(rest, [record | validated])
  end

  defp surrogate_pair?(first, last) do
    first.category == "Cs" and last.category == "Cs" and
      last.codepoint in 0xD800..0xDFFF and first.codepoint <= last.codepoint and
      String.starts_with?(first.name, "<") and String.ends_with?(first.name, ", First>") and
      String.starts_with?(last.name, "<") and String.ends_with?(last.name, ", Last>") and
      String.replace_suffix(first.name, "First>", "") ==
        String.replace_suffix(last.name, "Last>", "") and
      first.fields == last.fields and first.decomposition == ""
  end

  defp canonical_decomposition!(""), do: nil

  defp canonical_decomposition!(decomposition) do
    case String.split(decomposition) do
      ["<" <> _rest = tag | mapping] ->
        unless Regex.match?(~r/^<[^<>\s]+>$/, tag) and mapping != [] do
          raise ArgumentError, "malformed compatibility decomposition: #{inspect(decomposition)}"
        end

        Enum.each(mapping, &codepoint!(&1, :decomposition))
        nil

      mapping ->
        Enum.map(mapping, &codepoint!(&1, :decomposition))
    end
  end

  defp range_record!(line) do
    case String.split(line, ";", trim: false) do
      [range, value] ->
        {first, last} = scalar_range!(String.trim(range))
        {first, last, integer!(String.trim(value))}

      _fields ->
        raise ArgumentError, "malformed range record: #{inspect(line)}"
    end
  end

  defp scalar_range!(range) do
    case String.split(range, "..", trim: false) do
      [code] ->
        scalar = codepoint!(code, :range)
        {scalar, scalar}

      [first, last] ->
        first = codepoint!(first, :range)
        last = codepoint!(last, :range)

        if first > last do
          raise ArgumentError, "descending Unicode range: #{range}"
        end

        unless scalar_range?(first, last) do
          raise ArgumentError, "invalid Unicode scalar range: #{range}"
        end

        {first, last}

      _invalid ->
        raise ArgumentError, "malformed Unicode range: #{range}"
    end
  end

  defp reject_overlapping_ranges!(ranges) do
    Enum.reduce(ranges, [], fn
      {first, _last, _value}, [{_previous_first, previous_last, _} | _]
      when first <= previous_last ->
        raise ArgumentError,
              "overlapping Unicode ranges at #{hex(first)} and #{hex(previous_last)}"

      range, checked ->
        [range | checked]
    end)
    |> Enum.reverse()
  end

  defp coalesce_ranges(ranges) do
    Enum.reduce(ranges, [], fn
      {first, last, value}, [{previous_first, previous_last, value} | rest]
      when first == previous_last + 1 ->
        [{previous_first, last, value} | rest]

      range, coalesced ->
        [range | coalesced]
    end)
    |> Enum.reverse()
  end

  defp data_lines(input) do
    input
    |> String.split(~r/\r\n|\n|\r/)
    |> Enum.map(fn line ->
      line
      |> String.split("#", parts: 2)
      |> hd()
      |> String.trim()
    end)
    |> Enum.reject(&(&1 == ""))
  end

  defp codepoint!(hexadecimal, context) do
    parsed = Integer.parse(hexadecimal, 16)

    if Regex.match?(~r/^[0-9A-F]{4,6}$/, hexadecimal) do
      case parsed do
        {codepoint, ""}
        when codepoint in 0..0x10FFFF and codepoint not in 0xD800..0xDFFF ->
          codepoint

        {codepoint, ""} when context == :unicode_data and codepoint in 0xD800..0xDFFF ->
          codepoint

        _invalid ->
          raise ArgumentError, "invalid Unicode scalar: #{inspect(hexadecimal)}"
      end
    else
      raise ArgumentError, "invalid uppercase hexadecimal scalar: #{inspect(hexadecimal)}"
    end
  end

  defp integer!(decimal) do
    case Integer.parse(decimal, 10) do
      {integer, ""} when integer in 0..0xFFFF -> integer
      _invalid -> raise ArgumentError, "invalid non-negative 16-bit integer: #{inspect(decimal)}"
    end
  end

  defp scalar_range?(first, last) do
    first <= last and (last < 0xD800 or first > 0xDFFF)
  end

  defp hex(codepoint), do: codepoint |> Integer.to_string(16) |> String.upcase()
end
