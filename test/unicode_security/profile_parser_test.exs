defmodule UnicodeSecurity.ProfileParserTest do
  use ExUnit.Case, async: true
  alias UnicodeSecurity.UnicodeData.{ProfileGenerator, ProfileParser}

  test "accepts exact headers and defaults, and validates selected and unselected properties" do
    assert ProfileParser.prop_list!(
             header("PropList") <>
               "0020; White_Space\n202E; Bidi_Control\n0041; Other_Alphabetic\n"
           ) == %{white_space: [{32, 32, 1}], bidi_control: [{0x202E, 0x202E, 1}]}

    assert ProfileParser.joining_types!(
             header("DerivedJoiningType") <> "# @missing: 0000..10FFFF; Non_Joining\n0628; D\n"
           ) == [{0x628, 0x628, :d}]

    assert ProfileParser.vowels!(
             header("IndicSyllabicCategory") <>
               "# @missing: 0000..10FFFF; Other\n093E; Vowel_Dependent\n0915; Consonant\n"
           ) == [{0x93E, 0x93E, 1}]

    assert ProfileParser.exclusions!(
             normalization_header() <>
               "0344; Full_Composition_Exclusion\n0041; NFKC_CF; 0061\n0042; NFC_QC; M\n"
           ) == [{0x344, 0x344, 1}]
  end

  test "rejects missing, duplicate, and incorrect header/default declarations" do
    for input <- [
          "",
          header("DerivedJoiningType"),
          header("DerivedJoiningType") <> "# @missing: 0000..10FFFF; Other\n",
          header("DerivedJoiningType") <>
            String.duplicate("# @missing: 0000..10FFFF; Non_Joining\n", 2)
        ] do
      assert_raise ArgumentError, fn -> ProfileParser.joining_types!(input) end
    end

    assert_raise ArgumentError, fn ->
      ProfileParser.prop_list!(header("PropList") <> "# @missing: 0000..10FFFF; No\n")
    end

    assert_raise ArgumentError, fn ->
      ProfileParser.exclusions!(header("DerivedNormalizationProps"))
    end
  end

  test "rejects malformed, unknown, duplicate and overlapping records including ignored properties" do
    for row <- [
          "0020",
          "0020; Unknown",
          "0020; White_Space; Y",
          "0020; White_Space\n0020; White_Space",
          "0041..0044; Other_Alphabetic\n0043; Other_Alphabetic",
          "0044..0041; White_Space",
          "d800; White_Space",
          "D800; White_Space",
          "110000; White_Space",
          "0020...0021; White_Space"
        ] do
      assert_raise ArgumentError, fn -> ProfileParser.prop_list!(header("PropList") <> row) end
    end

    for row <- ["0041; NFC_QC; X", "0041; FC_NFKC;", "0041; NFKC_CF; D800", "0041; Unknown"] do
      assert_raise ArgumentError, fn ->
        ProfileParser.exclusions!(normalization_header() <> row)
      end
    end

    assert_raise ArgumentError, fn ->
      ProfileParser.joining_types!(
        header("DerivedJoiningType") <> "# @missing: 0000..10FFFF; Non_Joining\n0041; X"
      )
    end

    assert_raise ArgumentError, fn ->
      ProfileParser.vowels!(
        header("IndicSyllabicCategory") <> "# @missing: 0000..10FFFF; Other\n0041; Unknown"
      )
    end
  end

  test "rejects malformed joining fields, cross-surrogate category ranges, and excess range endpoints" do
    assert_raise ArgumentError, fn ->
      ProfileParser.joining_types!(
        header("DerivedJoiningType") <> "# @missing: 0000..10FFFF; Non_Joining\n0041"
      )
    end

    assert_raise ArgumentError, fn ->
      ProfileParser.categories!(
        record("D7FF", "<TEST, First>", "Lo") <> record("E000", "<TEST, Last>", "Lo")
      )
    end

    assert_raise ArgumentError, fn ->
      ProfileParser.prop_list!(header("PropList") <> "0020..0021..0022; White_Space")
    end
  end

  test "expands matched First/Last categories and rejects invalid ranges and categories" do
    assert ProfileParser.categories!(
             record("0041", "A", "Lu") <>
               record("20000", "<TEST, First>", "Lo") <> record("20002", "<TEST, Last>", "Lo")
           ) == [{0x41, 0x41, :lu}, {0x20000, 0x20002, :lo}]

    assert ProfileParser.categories!(
             record("D800", "<SURROGATE, First>", "Cs") <>
               record("DBFF", "<SURROGATE, Last>", "Cs")
           ) == []

    for input <- [
          "bad",
          record("0041", "A", "XX"),
          record("0041", "A", "Lu") <> record("0041", "A", "Lu"),
          record("20000", "<TEST, First>", "Lo"),
          record("20000", "<TEST, Last>", "Lo"),
          record("20000", "<TEST, First>", "Lo") <> record("20002", "<OTHER, Last>", "Lo"),
          record("20000", "<TEST, First>", "Lo") <> record("20002", "<TEST, Last>", "Lu"),
          record("20002", "<TEST, First>", "Lo") <> record("20000", "<TEST, Last>", "Lo")
        ] do
      assert_raise ArgumentError, fn -> ProfileParser.categories!(input) end
    end
  end

  test "filters full composition exclusions and rejects duplicate composition pairs" do
    assert ProfileGenerator.composition_pairs!(
             %{0xE9 => [0x65, 0x301], 0x344 => [0x308, 0x301], 0x212B => [0xC5]},
             [{0x344, 0x344, 1}]
           ) == [{0x65, 0x301, 0xE9}]

    assert_raise ArgumentError, fn ->
      ProfileGenerator.composition_pairs!(%{0xE9 => [0x65, 0x301], 0x1200 => [0x65, 0x301]}, [])
    end
  end

  defp header(name), do: "# #{name}-18.0.0.txt\n"
  defp record(code, name, category), do: "#{code};#{name};#{category};0;L;;;;;N;;;;;\n"

  defp normalization_header do
    header("DerivedNormalizationProps") <>
      Enum.map_join(
        [
          "NFD_QC; Yes",
          "NFC_QC; Yes",
          "NFKD_QC; Yes",
          "NFKC_QC; Yes",
          "NFKC_CF; <code point>",
          "NFKC_SCF; <code point>"
        ],
        &"# @missing: 0000..10FFFF; #{&1}\n"
      )
  end
end
