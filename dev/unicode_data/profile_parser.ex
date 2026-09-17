defmodule UnicodeSecurity.UnicodeData.ProfileParser do
  @moduledoc false

  alias UnicodeSecurity.UnicodeData.Parser

  @categories Enum.zip(
                ~w(Cn Lu Ll Lt Lm Lo Mn Mc Me Nd Nl No Pc Pd Ps Pe Pi Pf Po Sm Sc Sk So Zs Zl Zp Cc Cf Cs Co),
                [
                  :cn,
                  :lu,
                  :ll,
                  :lt,
                  :lm,
                  :lo,
                  :mn,
                  :mc,
                  :me,
                  :nd,
                  :nl,
                  :no,
                  :pc,
                  :pd,
                  :ps,
                  :pe,
                  :pi,
                  :pf,
                  :po,
                  :sm,
                  :sc,
                  :sk,
                  :so,
                  :zs,
                  :zl,
                  :zp,
                  :cc,
                  :cf,
                  :cs,
                  :co
                ]
              )
              |> Map.new()
  @joining %{"U" => :u, "R" => :r, "L" => :l, "D" => :d, "C" => :c, "T" => :t}
  @binary_properties ~w(ASCII_Hex_Digit Bidi_Control Dash Deprecated Diacritic Extender Hex_Digit Hyphen IDS_Binary_Operator IDS_Trinary_Operator IDS_Unary_Operator ID_Compat_Math_Continue ID_Compat_Math_Start Ideographic Join_Control Logical_Order_Exception Modifier_Combining_Mark Noncharacter_Code_Point Other_Alphabetic Other_Default_Ignorable_Code_Point Other_Grapheme_Extend Other_ID_Continue Other_ID_Start Other_Lowercase Other_Math Other_Uppercase Pattern_Syntax Pattern_White_Space Prepended_Concatenation_Mark Quotation_Mark Radical Regional_Indicator Sentence_Terminal Soft_Dotted Terminal_Punctuation Unified_Ideograph Variation_Selector White_Space)
  @indic_values ~w(Other Avagraha Bindu Brahmi_Joining_Number Cantillation_Mark Consonant Consonant_Dead Consonant_Final Consonant_Head_Letter Consonant_Initial_Postfixed Consonant_Killer Consonant_Medial Consonant_Placeholder Consonant_Preceding_Repha Consonant_Prefixed Consonant_Subjoined Consonant_Succeeding_Repha Consonant_With_Stacker Gemination_Mark Invisible_Stacker Joiner Modifying_Letter Non_Joiner Nukta Number Number_Joiner Pure_Killer Register_Shifter Reordering_Killer Syllable_Modifier Tone_Letter Tone_Mark Virama Visarga Vowel Vowel_Dependent Vowel_Independent)
  @normalization_binary ~w(Full_Composition_Exclusion Changes_When_NFKC_Casefolded Expands_On_NFC Expands_On_NFD Expands_On_NFKC Expands_On_NFKD)
  @normalization_defaults Enum.map(
                            [
                              "NFD_QC; Yes",
                              "NFC_QC; Yes",
                              "NFKD_QC; Yes",
                              "NFKC_QC; Yes",
                              "NFKC_CF; <code point>",
                              "NFKC_SCF; <code point>"
                            ],
                            &"# @missing: 0000..10FFFF; #{&1}"
                          )

  @spec prop_list!(binary()) :: map()
  def prop_list!(input) do
    header_defaults!(input, "PropList", [])

    groups =
      grouped!(input, fn
        [range, name] when name in @binary_properties -> {name, range, 1}
        fields -> malformed!(fields)
      end)

    %{
      white_space: Map.get(groups, "White_Space", []),
      bidi_control: Map.get(groups, "Bidi_Control", [])
    }
  end

  @spec joining_types!(binary()) :: [tuple()]
  def joining_types!(input) do
    header_defaults!(input, "DerivedJoiningType", ["# @missing: 0000..10FFFF; Non_Joining"])

    input
    |> grouped!(fn
      [range, value] -> {"Joining_Type", range, closed!(@joining, value)}
      fields -> malformed!(fields)
    end)
    |> Map.get("Joining_Type", [])
  end

  @spec vowels!(binary()) :: [tuple()]
  def vowels!(input) do
    header_defaults!(input, "IndicSyllabicCategory", ["# @missing: 0000..10FFFF; Other"])

    input
    |> grouped!(fn
      [range, value] when value in @indic_values -> {"Indic_Syllabic_Category", range, value}
      fields -> malformed!(fields)
    end)
    |> Map.get("Indic_Syllabic_Category", [])
    |> Enum.flat_map(fn
      {first, last, "Vowel_Dependent"} -> [{first, last, 1}]
      _record -> []
    end)
  end

  @spec exclusions!(binary()) :: [tuple()]
  def exclusions!(input) do
    header_defaults!(input, "DerivedNormalizationProps", @normalization_defaults)
    input |> grouped!(&normalization_record!/1) |> Map.get("Full_Composition_Exclusion", [])
  end

  defp normalization_record!([range, name]) when name in @normalization_binary,
    do: {name, range, 1}

  defp normalization_record!([range, name, value])
       when name in ["NFD_QC", "NFKD_QC"] and value == "N",
       do: {name, range, value}

  defp normalization_record!([range, name, value])
       when name in ["NFC_QC", "NFKC_QC"] and value in ["N", "M"],
       do: {name, range, value}

  defp normalization_record!([range, name, mapping])
       when name in ["FC_NFKC", "NFKC_CF", "NFKC_SCF"] do
    if name == "FC_NFKC" and mapping == "", do: malformed!([range, name, mapping])
    Enum.each(String.split(mapping), &point!(&1, false))
    {name, range, mapping}
  end

  defp normalization_record!(fields), do: malformed!(fields)

  @spec categories!(binary()) :: [tuple()]
  def categories!(input) do
    # Validate every UnicodeData mapping and duplicate/surrogate record as well.
    Parser.unicode_data!(input)

    input
    |> lines()
    |> Enum.map(fn line ->
      [code, name, category | properties] = String.split(line, ";")
      {point!(code, true), name, closed!(@categories, category), properties}
    end)
    |> category_ranges!([])
    |> ordered!()
    |> coalesce()
  end

  defp category_ranges!([], acc), do: Enum.reverse(acc)

  defp category_ranges!([{first, name, category, properties} | rest], acc) do
    cond do
      String.ends_with?(name, ", First>") ->
        {last, remaining} = category_last!(rest, first, name, category, properties)
        category_ranges!(remaining, category_range!(first, last, category) ++ acc)

      String.ends_with?(name, ", Last>") ->
        malformed!([name])

      true ->
        category_ranges!(rest, category_range!(first, first, category) ++ acc)
    end
  end

  defp category_last!(
         [{last, last_name, category, properties} | remaining],
         first,
         name,
         category,
         properties
       ) do
    unless String.starts_with?(name, "<") and first < last and
             String.replace_suffix(name, "First>", "Last>") == last_name,
           do: malformed!([name, last_name])

    {last, remaining}
  end

  defp category_last!(_rest, _first, name, _category, _properties), do: malformed!([name])

  defp category_range!(first, last, :cs) when first in 0xD800..0xDFFF and last in 0xD800..0xDFFF,
    do: []

  defp category_range!(first, last, category) do
    unless last < 0xD800 or first > 0xDFFF, do: malformed!([first, last, category])
    [{first, last, category}]
  end

  defp header_defaults!(input, name, expected) do
    raw = String.split(input, "\n") |> Enum.map(&String.trim/1)
    headers = Enum.filter(raw, &String.starts_with?(&1, "# #{name}-"))

    unless hd(raw) == "# #{name}-18.0.0.txt" and headers == ["# #{name}-18.0.0.txt"],
      do: raise(ArgumentError, "invalid #{name} Unicode 18.0.0 header")

    defaults = Enum.filter(raw, &String.contains?(&1, "@missing:"))
    unless defaults == expected, do: raise(ArgumentError, "invalid #{name} defaults")
  end

  defp grouped!(input, parser) do
    input
    |> lines()
    |> Enum.map(fn line ->
      fields = line |> String.split(";") |> Enum.map(&String.trim/1)
      {name, range, value} = parser.(fields)
      {first, last} = range!(range)
      {name, {first, last, value}}
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Map.new(fn {name, records} -> {name, records |> ordered!() |> coalesce()} end)
  end

  defp ordered!(records) do
    sorted = Enum.sort(records)

    _last =
      Enum.reduce(sorted, -1, fn {first, last, _}, previous ->
        if first <= previous, do: raise(ArgumentError, "overlapping profile property ranges")
        last
      end)

    sorted
  end

  defp coalesce(records) do
    records
    |> Enum.reduce([], fn
      {first, last, value}, [{start, previous, value} | rest] when first == previous + 1 ->
        [{start, last, value} | rest]

      record, acc ->
        [record | acc]
    end)
    |> Enum.reverse()
  end

  defp range!(value) do
    points = value |> String.split("..") |> Enum.map(&point!(&1, false))
    unless length(points) in 1..2, do: malformed!([value])
    first = hd(points)
    last = List.last(points)
    unless first <= last and (last < 0xD800 or first > 0xDFFF), do: malformed!([value])
    {first, last}
  end

  defp point!(value, surrogate?) do
    unless Regex.match?(~r/\A[0-9A-F]{4,6}\z/, value), do: malformed!([value])
    point = String.to_integer(value, 16)

    unless point <= 0x10FFFF and (surrogate? or point not in 0xD800..0xDFFF),
      do: malformed!([value])

    point
  end

  defp closed!(values, value) do
    case Map.fetch(values, value) do
      {:ok, result} -> result
      :error -> raise ArgumentError, "unknown profile property value: #{inspect(value)}"
    end
  end

  defp lines(input),
    do:
      input
      |> String.split("\n")
      |> Enum.map(&(String.split(&1, "#", parts: 2) |> hd() |> String.trim()))
      |> Enum.reject(&(&1 == ""))

  defp malformed!(fields),
    do: raise(ArgumentError, "malformed profile property record: #{inspect(fields)}")
end
