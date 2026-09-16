defmodule UnicodeSecurity.UnicodeData.Parser do
  @moduledoc false

  @type codepoint :: 0..0x10FFFF
  @type range_record :: {codepoint(), codepoint(), non_neg_integer()}

  @bidi_classes ~w(L R AL EN ES ET AN CS NSM BN B S WS ON LRE LRO RLE RLO PDF LRI RLI FSI PDI)
  @bidi_codes @bidi_classes |> Enum.with_index() |> Map.new()
  @core_properties ~w(Alphabetic Case_Ignorable Cased Changes_When_Casefolded
    Changes_When_Casemapped Changes_When_Lowercased Changes_When_Titlecased
    Changes_When_Uppercased Default_Ignorable_Code_Point Grapheme_Base Grapheme_Extend
    Grapheme_Link ID_Continue ID_Start Lowercase Math Uppercase XID_Continue XID_Start)

  @spec default_ignorables!(binary()) :: [range_record()]
  def default_ignorables!(input) do
    version_header!(input, "DerivedCoreProperties")

    input
    |> data_lines()
    |> Enum.flat_map(&core_property!/1)
    |> sorted_ranges!()
  end

  defp core_property!(line) do
    case fields(line) do
      [range, property] when property in @core_properties ->
        {first, last} = scalar_range!(range)
        if property == "Default_Ignorable_Code_Point", do: [{first, last, 1}], else: []

      [range, "InCB", value] when value in ["Linker", "Consonant", "Extend"] ->
        scalar_range!(range)
        []

      _ ->
        raise ArgumentError, "malformed DerivedCoreProperties record: #{inspect(line)}"
    end
  end

  @spec bidi_classes!(binary()) :: [range_record()]
  def bidi_classes!(input) do
    version_header!(input, "DerivedBidiClass")
    defaults = bidi_defaults!(input)

    explicit =
      input
      |> data_lines()
      |> Enum.map(fn line ->
        case fields(line) do
          [range, class] ->
            {first, last} = scalar_range!(range)
            {first, last, bidi_code!(class)}

          _ ->
            raise ArgumentError, "malformed DerivedBidiClass record: #{inspect(line)}"
        end
      end)
      |> sorted_ranges!()

    Enum.reduce(defaults ++ explicit, [{0, 0xD7FF, 0}, {0xE000, 0x10FFFF, 0}], &overlay_range/2)
    |> Enum.reject(fn {_first, _last, value} -> value == 0 end)
    |> coalesce_ranges()
  end

  @spec bidi_brackets!(binary()) :: [{codepoint(), codepoint(), 1 | 2}]
  def bidi_brackets!(input) do
    version_header!(input, "BidiBrackets")

    input
    |> data_lines()
    |> Enum.map(&bracket_record!/1)
    |> reciprocal_pairs!()
  end

  defp bracket_record!(line) do
    case fields(line) do
      [code, pair, kind] when kind in ["o", "c"] ->
        {codepoint!(code, :bracket), codepoint!(pair, :bracket), if(kind == "o", do: 1, else: 2)}

      _ ->
        raise ArgumentError, "malformed BidiBrackets record: #{inspect(line)}"
    end
  end

  @spec bidi_mirroring!(binary()) :: [{codepoint(), codepoint(), 0}]
  def bidi_mirroring!(input) do
    version_header!(input, "BidiMirroring")

    input
    |> data_lines()
    |> Enum.map(fn line ->
      case fields(line) do
        [code, pair] -> {codepoint!(code, :mirror), codepoint!(pair, :mirror), 0}
        _ -> raise ArgumentError, "malformed BidiMirroring record: #{inspect(line)}"
      end
    end)
    |> reciprocal_pairs!()
  end

  @spec nonspacing_marks!(binary()) :: [range_record()]
  def nonspacing_marks!(input) do
    input
    |> records!()
    |> validate_unicode_data_records!()
    |> Enum.flat_map(fn record ->
      canonical_decomposition!(record.decomposition)

      if record.category in ["Mn", "Me"] do
        [{record.codepoint, record.codepoint, 1}]
      else
        []
      end
    end)
    |> sorted_ranges!()
  end

  @spec decimal_zeros!(binary()) :: [{codepoint(), codepoint(), codepoint()}]
  def decimal_zeros!(input) do
    input
    |> records!()
    |> validate_unicode_data_records!()
    |> Enum.flat_map(&decimal_record!/1)
    |> Enum.group_by(fn {code, value} -> code - value end)
    |> Enum.map(fn {zero, digits} ->
      unless zero >= 0 and Enum.sort(digits) == Enum.map(0..9, &{zero + &1, &1}) do
        raise ArgumentError, "inconsistent UnicodeData decimal system at #{hex(zero)}"
      end

      {zero, zero + 9, zero}
    end)
    |> Enum.sort()
  end

  defp decimal_record!(record) do
    [_, _, _, _, decimal, digit, numeric | _] = record.fields

    cond do
      record.category == "Nd" ->
        unless decimal in ~w(0 1 2 3 4 5 6 7 8 9) and digit == decimal and numeric == decimal do
          raise ArgumentError, "inconsistent UnicodeData decimal fields at #{record.code}"
        end

        [{record.codepoint, String.to_integer(decimal)}]

      decimal != "" ->
        raise ArgumentError, "UnicodeData decimal value on non-Nd scalar at #{record.code}"

      true ->
        []
    end
  end

  defp bidi_defaults!(input) do
    missing =
      input
      |> String.split(~r/\r\n|\n|\r/)
      |> Enum.filter(&String.contains?(&1, "@missing:"))
      |> Enum.map(fn line ->
        case Regex.run(~r/^#\s*@missing:\s*(\S+)\s*;\s*(\w+)\s*$/, line) do
          [_, "0000..10FFFF", "Left_To_Right"] -> {0, 0x10FFFF, 0}
          [_, range, class] -> missing_range!(range, class)
          _ -> raise ArgumentError, "malformed bidi @missing record: #{inspect(line)}"
        end
      end)

    case missing do
      [{0, 0x10FFFF, 0} | defaults] -> sorted_ranges!(defaults)
      _ -> raise ArgumentError, "DerivedBidiClass requires the global Left_To_Right default"
    end
  end

  defp missing_range!(range, class) do
    {first, last} = scalar_range!(range)

    value =
      case class do
        "Right_To_Left" -> 1
        "Arabic_Letter" -> 2
        "European_Terminator" -> 5
        _ -> raise ArgumentError, "unsupported bidi @missing class: #{inspect(class)}"
      end

    {first, last, value}
  end

  defp bidi_code!(class) do
    case Map.fetch(@bidi_codes, class) do
      {:ok, code} -> code
      :error -> raise ArgumentError, "unknown bidi class: #{inspect(class)}"
    end
  end

  defp overlay_range({first, last, value}, ranges) do
    Enum.flat_map(ranges, &overlay_segment(&1, first, last, value))
  end

  defp overlay_segment({start, stop, original} = range, first, last, value) do
    if last < start or first > stop do
      [range]
    else
      left = if start < first, do: [{start, first - 1, original}], else: []
      right = if stop > last, do: [{last + 1, stop, original}], else: []
      left ++ [{max(start, first), min(stop, last), value}] ++ right
    end
  end

  defp reciprocal_pairs!(pairs) do
    by_code = Map.new(pairs, fn {code, pair, kind} -> {code, {pair, kind}} end)

    if map_size(by_code) != length(pairs) do
      raise ArgumentError, "duplicate bidi pair source"
    end

    Enum.each(pairs, fn {code, pair, kind} ->
      opposite = if kind == 0, do: 0, else: 3 - kind

      unless pair != code and Map.get(by_code, pair) == {code, opposite} do
        raise ArgumentError, "nonreciprocal bidi pair at #{hex(code)}"
      end
    end)

    Enum.sort(pairs)
  end

  defp version_header!(input, name) do
    unless String.starts_with?(input, "# #{name}-18.0.0.txt\n") or
             String.starts_with?(input, "# #{name}-18.0.0.txt\r\n") do
      raise ArgumentError, "invalid #{name} Unicode 18.0.0 version header"
    end
  end

  defp fields(line), do: line |> String.split(";", trim: false) |> Enum.map(&String.trim/1)

  defp sorted_ranges!(ranges) do
    ranges
    |> Enum.sort_by(fn {first, last, _value} -> {first, last} end)
    |> reject_overlapping_ranges!()
    |> coalesce_ranges()
  end

  @spec confusables!(binary()) :: %{codepoint() => [codepoint()]}
  def confusables!(input) when is_binary(input) do
    input
    |> data_lines()
    |> Enum.reduce(%{}, fn line, mappings ->
      case line |> String.split(";", trim: false) |> Enum.map(&String.trim/1) do
        [source, target, "MA"] when target != "" ->
          scalar = codepoint!(source, :confusables)
          mapping = target |> String.split() |> Enum.map(&codepoint!(&1, :confusables))

          put_mapping!(mappings, scalar, mapping)

        _fields ->
          raise ArgumentError, "malformed MA confusable record: #{inspect(line)}"
      end
    end)
  end

  defp put_mapping!(mappings, scalar, mapping) do
    if Map.has_key?(mappings, scalar) do
      raise ArgumentError, "duplicate confusable source: #{hex(scalar)}"
    end

    Map.put(mappings, scalar, mapping)
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
      sentinel_names_match?(first.name, last.name) and
      first.fields == last.fields and first.decomposition == ""
  end

  defp sentinel_names_match?(first, last) do
    String.starts_with?(first, "<") and String.ends_with?(first, ", First>") and
      String.starts_with?(last, "<") and String.ends_with?(last, ", Last>") and
      String.replace_suffix(first, "First>", "") == String.replace_suffix(last, "Last>", "")
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
