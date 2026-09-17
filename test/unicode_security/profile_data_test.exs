defmodule UnicodeSecurity.ProfileDataTest do
  use ExUnit.Case, async: true
  alias UnicodeSecurity.Data.{Composition, Profile}

  test "looks up pinned profile properties" do
    assert Profile.category(?A) == :lu
    assert Profile.white_space?(0x2003)
    assert Profile.bidi_control?(0x202E)
    assert Profile.joining_type(0x0628) == :d
    assert Profile.vowel_dependent?(0x093E)
    assert Profile.category(0x20000) == :lo
    assert Profile.category(0x10FFFF) == :cn
    refute Profile.white_space?(?A)
    refute Profile.bidi_control?(?A)
    refute Profile.vowel_dependent?(?A)
    assert Profile.joining_type(?A) == :u
    assert Composition.compose(?e, 0x301) == 0xE9
    assert Composition.compose(0x915, 0x93C) == nil
    assert Composition.compose(0x1D157, 0x1D165) == nil
    assert Composition.compose(0x1100, 0x1161) == nil
    assert Composition.compose(0x10FFFF, 0x10FFFF) == nil
  end

  test "matches independently interpreted pinned properties for every Unicode scalar" do
    properties = fixture("PropList.txt")
    whitespace = property_map(properties, "White_Space")
    controls = property_map(properties, "Bidi_Control")
    vowels = fixture("IndicSyllabicCategory.txt") |> property_map("Vowel_Dependent")

    joining =
      fixture("DerivedJoiningType.txt")
      |> Enum.reduce(%{}, fn [range, value], map ->
        Enum.reduce(points(range), map, &Map.put(&2, &1, value))
      end)

    {categories, nil} =
      fixture("UnicodeData.txt")
      |> Enum.reduce({%{}, nil}, fn [code, name, category | _], {map, pending} ->
        point = String.to_integer(code, 16)

        cond do
          String.ends_with?(name, ", First>") ->
            {map, point}

          String.ends_with?(name, ", Last>") ->
            {Enum.reduce(pending..point, map, &Map.put(&2, &1, category)), nil}

          true ->
            {Map.put(map, point, category), nil}
        end
      end)

    for code <- 0..0x10FFFF, code not in 0xD800..0xDFFF do
      assert Atom.to_string(Profile.category(code)) ==
               String.downcase(Map.get(categories, code, "Cn")),
             "category U+#{Integer.to_string(code, 16)}"

      assert Profile.white_space?(code) == Map.has_key?(whitespace, code)
      assert Profile.bidi_control?(code) == Map.has_key?(controls, code)
      assert Profile.vowel_dependent?(code) == Map.has_key?(vowels, code)

      assert Atom.to_string(Profile.joining_type(code)) ==
               String.downcase(Map.get(joining, code, "U"))
    end
  end

  test "every canonical pair is generated exactly when not fully excluded" do
    excluded =
      fixture("DerivedNormalizationProps.txt")
      |> Enum.filter(&(Enum.at(&1, 1) == "Full_Composition_Exclusion"))
      |> Enum.reduce(MapSet.new(), fn [range, _], set ->
        Enum.reduce(points(range), set, &MapSet.put(&2, &1))
      end)

    pairs =
      fixture("UnicodeData.txt")
      |> Enum.flat_map(fn [code, _, _, _, _, mapping | _] ->
        case String.split(mapping) do
          [first, second] ->
            if String.starts_with?(first, "<"),
              do: [],
              else: [
                {String.to_integer(code, 16), String.to_integer(first, 16),
                 String.to_integer(second, 16)}
              ]

          _ ->
            []
        end
      end)

    for {code, first, second} <- pairs do
      expected = if MapSet.member?(excluded, code), do: nil, else: code
      assert Composition.compose(first, second) == expected
    end

    assert length(pairs) > 1000
  end

  defp fixture(name) do
    Path.join("priv/unicode/18.0.0-draft", name)
    |> File.read!()
    |> String.split("\n")
    |> Enum.map(&(String.split(&1, "#", parts: 2) |> hd() |> String.trim()))
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&(String.split(&1, ";") |> Enum.map(fn field -> String.trim(field) end)))
  end

  defp points(range) do
    values = range |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))
    hd(values)..List.last(values)
  end

  defp property_map(records, name) do
    records
    |> Enum.filter(&(Enum.at(&1, 1) == name))
    |> Enum.reduce(%{}, fn [range, _], map ->
      Enum.reduce(points(range), map, &Map.put(&2, &1, true))
    end)
  end
end
