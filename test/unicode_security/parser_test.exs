defmodule UnicodeSecurity.ParserTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Packer
  alias UnicodeSecurity.UnicodeData.Parser

  test "parses canonical decompositions and excludes compatibility mappings" do
    input =
      "00C0;LATIN CAPITAL LETTER A WITH GRAVE;Lu;0;L;0041 0300;;;;N;;;;00E0;\n" <>
        "00A0;NO-BREAK SPACE;Zs;0;CS;<noBreak> 0020;;;;N;;;;;\n"

    assert Parser.unicode_data!(input) == %{0x00C0 => [0x0041, 0x0300]}
  end

  test "parses and coalesces combining-class ranges" do
    input = "0300..0314 ; 230 # Mn\n0315 ; 232 # Mn\n"

    assert Parser.ranges!(input, :integer) == [
             {0x0300, 0x0314, 230},
             {0x0315, 0x0315, 232}
           ]
  end

  test "rejects surrogate range sentinels with mismatched properties" do
    input =
      "D800;<High Surrogate, First>;Cs;0;L;;;;;N;;;;;\n" <>
        "DB7F;<High Surrogate, Last>;Cs;1;L;;;;;N;;;;;\n"

    assert_raise ArgumentError, ~r/unpaired UnicodeData surrogate range/, fn ->
      Parser.unicode_data!(input)
    end
  end

  test "rejects scalar endpoints whose range crosses the surrogate block" do
    assert_raise ArgumentError, ~r/Unicode scalar range/, fn ->
      Parser.ranges!("D7FF..E000 ; 0\n", :integer)
    end
  end

  test "packs sorted ranges into fixed-width binary records" do
    packed = Packer.ranges([{0x0300, 0x0314, 230}, {0x0315, 0x0315, 232}])

    assert packed ==
             <<0x0300::32, 0x0314::32, 230::16, 0x0315::32, 0x0315::32, 232::16>>
  end

  test "refuses to pack a range crossing the surrogate block" do
    assert_raise ArgumentError, ~r/Unicode scalar range/, fn ->
      Packer.ranges([{0xD7FF, 0xE000, 0}])
    end
  end

  test "packs variable mappings with an index" do
    {index, values} = Packer.mapping([{0x00C0, [0x0041, 0x0300]}])

    assert index == <<0x00C0::32, 0::32, 2::16>>
    assert values == <<0x0041::32, 0x0300::32>>
  end
end
