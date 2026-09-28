defmodule UnicodeSecurity.DomainSourceTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Domain.Source
  alias UnicodeSecurity.Utf8

  test "preserves source labels and all original separators" do
    input = "a。b．c｡d.\u00AD"
    units = Source.units(input, Utf8.decode!(input))
    labels = Enum.filter(units, &(&1.kind == :label))
    separators = Enum.filter(units, &(&1.kind == :separator))
    assert Enum.map(labels, & &1.input) == ["a", "b", "c", "d", "\u00AD"]
    assert Enum.map(separators, & &1.input) == ["。", "．", "｡", "."]
    assert Enum.map(labels, & &1.codepoint_index) == [0, 2, 4, 6, 8]
    assert Enum.map(labels, & &1.byte_offset) == [0, 4, 8, 12, 14]
  end

  test "retains leading, interior, final and whole-input empty labels" do
    assert Source.units("", []) |> Enum.map(& &1.input) == [""]

    assert Source.units(".a..", Utf8.decode!(".a.."))
           |> Enum.filter(&(&1.kind == :label))
           |> Enum.map(& &1.input) == ["", "a", "", ""]
  end
end
