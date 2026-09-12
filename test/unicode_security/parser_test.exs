defmodule UnicodeSecurity.ParserTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Packer
  alias UnicodeSecurity.UnicodeData.Parser

  # Catches dropped target scalars, silently overwritten duplicates, and lax MA parsing.
  test "parses MA confusables with scalar and multi-scalar targets" do
    input = "# header\r\n0430 ; 0061 ; MA # Cyrillic a\r\n006D ; 0072 006E ; MA\n"
    assert Parser.confusables!(input) == %{0x0430 => [0x0061], 0x006D => [0x0072, 0x006E]}
    assert Parser.confusables!("# comment only\n") == %{}
  end

  test "rejects duplicate confusable sources even with identical targets" do
    for target <- ["0061", "0062"] do
      assert_raise ArgumentError, ~r/duplicate/, fn ->
        Parser.confusables!("0430 ; 0061 ; MA\n0430 ; #{target} ; MA\n")
      end
    end
  end

  test "rejects every legacy mapping type and unknown or missing mapping types" do
    for type <- ["SL", "SA", "ML", "", "ma", "UNKNOWN", "MA MA"] do
      assert_raise ArgumentError, fn -> Parser.confusables!("0430 ; 0061 ; #{type}") end
    end
  end

  test "rejects malformed confusable fields and invalid source or target scalars" do
    for line <- [
          "0430 ; 0061",
          "0430 ; 0061 ; MA ; extra",
          "; 0061 ; MA",
          "0430 ; ; MA",
          "0430 0431 ; 0061 ; MA",
          "D800 ; 0061 ; MA",
          "110000 ; 0061 ; MA",
          "0430 ; DFFF ; MA",
          "0430 ; 0061 110000 ; MA",
          "0430 ; 006a ; MA",
          "0430..0431 ; 0061 ; MA",
          "0430 ; 61 ; MA"
        ] do
      assert_raise ArgumentError, fn -> Parser.confusables!(line) end
    end
  end

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

  test "rejects malformed, duplicate and unpaired UnicodeData records" do
    record = "0041;A;Lu;0;L;;;;;N;;;;;\n"

    for input <- ["0041;A", record <> record, "D800;<High Surrogate, First>;Cs;0;L;;;;;N;;;;;\n"] do
      assert_raise ArgumentError, fn -> Parser.unicode_data!(input) end
    end

    for decomposition <- ["<font>", "<bad 0041", "<> 0041"] do
      assert_raise ArgumentError, fn ->
        Parser.unicode_data!("0041;A;Lu;0;L;#{decomposition};;;;N;;;;;\n")
      end
    end
  end

  test "accepts surrogate sentinels without emitting scalar mappings" do
    input =
      "D800;<High Surrogate, First>;Cs;0;L;;;;;N;;;;;\n" <>
        "DB7F;<High Surrogate, Last>;Cs;0;L;;;;;N;;;;;\n"

    assert Parser.unicode_data!(input) == %{}
  end

  test "coalesces only adjacent equal ranges and rejects malformed ranges" do
    assert Parser.ranges!("0301 ; 230\n0300 ; 230", :integer) == [{0x0300, 0x0301, 230}]

    for input <- [
          "0300",
          "0300 ; 1 ; 2",
          "0301..0300 ; 1",
          "0300..0301..0302 ; 1",
          "0300..0301 ; 1\n0301 ; 2",
          "0300 ; -1",
          "0300 ; 65536",
          "0300 ; 1x"
        ] do
      assert_raise ArgumentError, fn -> Parser.ranges!(input, :integer) end
    end
  end

  test "rejects lossy packed fields, invalid scalars and unordered records" do
    for ranges <- [
          [{2, 1, 0}],
          [{1, 1, -1}],
          [{1, 1, 65_536}],
          [{0xD800, 0xD800, 0}],
          [{1, 2, 0}, {2, 3, 0}]
        ] do
      assert_raise ArgumentError, fn -> Packer.ranges(ranges) end
    end

    for mappings <- [
          [{1, []}],
          [{1, :invalid}],
          [{1, List.duplicate(1, 65_536)}],
          [{1, [0xD800]}],
          [{2, [1]}, {1, [1]}]
        ] do
      assert_raise ArgumentError, fn -> Packer.mapping(mappings) end
    end
  end

  test "mapping index records preserve maximal fields and reject overflow before truncation" do
    assert Packer.mapping_index!(0x10FFFF, 0xFFFFFFFF, 0xFFFF) ==
             <<0x10FFFF::32, 0xFFFFFFFF::32, 0xFFFF::16>>

    for {offset, count} <- [{0x100000000, 1}, {-1, 1}, {0, 0}, {0, 65_536}] do
      assert_raise ArgumentError, fn -> Packer.mapping_index!(1, offset, count) end
    end
  end
end
