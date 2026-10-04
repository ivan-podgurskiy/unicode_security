defmodule UnicodeSecurity.Test.BidiFixtures do
  @moduledoc false

  alias UnicodeSecurity.UnicodeData.Source

  @project_root Path.expand("../..", __DIR__)
  @directory Source.directory(@project_root)
  # Each representative has the required pinned Bidi_Class and is not a paired bracket.
  @representatives %{
    "L" => 0x61,
    "R" => 0x5D0,
    "AL" => 0x627,
    "EN" => 0x31,
    "ES" => 0x2B,
    "ET" => 0x24,
    "AN" => 0x661,
    "CS" => 0x2C,
    "NSM" => 0x300,
    "BN" => 0,
    "B" => 0x2029,
    "S" => 9,
    "WS" => 0x20,
    "ON" => 0x21,
    "LRE" => 0x202A,
    "LRO" => 0x202D,
    "RLE" => 0x202B,
    "RLO" => 0x202E,
    "PDF" => 0x202C,
    "LRI" => 0x2066,
    "RLI" => 0x2067,
    "FSI" => 0x2068,
    "PDI" => 0x2069
  }

  def type_rows do
    lines("BidiTest")
    |> Stream.transform({nil, nil}, fn
      {"@Levels:" <> text, _line}, {_levels, order} ->
        {[], {levels(text), order}}

      {"@Reorder:" <> text, _line}, {levels, _order} ->
        {[], {levels, integers(text)}}

      {text, line}, {levels, order} = state ->
        [types, bitset] = String.split(text, ";")
        scalars = types |> String.split() |> Enum.map(&Map.fetch!(@representatives, &1))

        directions =
          for {bit, direction} <- [{1, :auto}, {2, 0}, {4, 1}],
              Bitwise.band(String.to_integer(String.trim(bitset), 16), bit) != 0,
              do: direction

        true = length(levels) == length(scalars)
        {[{line, scalars, directions, levels, order}], state}
    end)
  end

  def character_rows do
    lines("BidiCharacterTest")
    |> Stream.map(fn {text, line} ->
      [codes, direction, paragraph, levels, order] = String.split(text, ";")
      scalars = codes |> String.split() |> Enum.map(&String.to_integer(&1, 16))

      direction =
        case direction do
          "0" -> 0
          "1" -> 1
          "2" -> :auto
        end

      {line, scalars, direction, String.to_integer(paragraph), levels(levels), integers(order)}
    end)
  end

  defp levels(text) do
    text
    |> String.split()
    |> Enum.map(fn
      "x" -> :x
      number -> String.to_integer(number)
    end)
  end

  defp integers(text), do: text |> String.split() |> Enum.map(&String.to_integer/1)

  defp lines(name) do
    path = Path.join(@directory, name <> ".txt")
    [header] = path |> File.stream!() |> Enum.take(1)
    true = String.trim(header) == "# #{name}-18.0.0.txt"

    path
    |> File.stream!()
    |> Stream.with_index(1)
    |> Stream.map(fn {line, number} ->
      {line |> String.split("#", parts: 2) |> hd() |> String.trim(), number}
    end)
    |> Stream.reject(fn {line, _number} -> line == "" end)
  end
end
