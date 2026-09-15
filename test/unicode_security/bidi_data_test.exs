defmodule UnicodeSecurity.BidiDataTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Packer
  alias UnicodeSecurity.UnicodeData.Parser

  test "packs bidi pairs without truncating scalar or kind fields" do
    assert Packer.pairs([{0x28, 0x29, 1}, {0x29, 0x28, 2}]) ==
             <<0x28::32, 0x29::32, 1, 0x29::32, 0x28::32, 2>>

    for pairs <- [
          [{0x28, 0xD800, 1}],
          [{0x28, 0x29, 3}],
          [{0x28, 0x29, 1}, {0x28, 0x29, 1}],
          [{0x29, 0x28, 2}, {0x28, 0x29, 1}]
        ] do
      assert_raise ArgumentError, fn -> Packer.pairs(pairs) end
    end
  end

  test "parses default-ignorables without confusing other core properties" do
    input = """
    # DerivedCoreProperties-18.0.0.txt
    0041 ; Alphabetic
    200C..200D ; Default_Ignorable_Code_Point
    FE00..FE0F ; Default_Ignorable_Code_Point
    094D ; InCB; Linker
    """

    assert Parser.default_ignorables!(input) == [{0x200C, 0x200D, 1}, {0xFE00, 0xFE0F, 1}]
  end

  test "resolves bidi missing defaults with explicit assignments taking precedence" do
    input = """
    # DerivedBidiClass-18.0.0.txt
    # @missing: 0000..10FFFF; Left_To_Right
    # @missing: 0590..05FF; Right_To_Left
    # @missing: 0600..07BF; Arabic_Letter
    # @missing: 20A0..20CF; European_Terminator
    05B0 ; NSM
    0610 ; NSM
    0041 ; L
    """

    assert Parser.bidi_classes!(input) == [
             {0x0590, 0x05AF, 1},
             {0x05B0, 0x05B0, 8},
             {0x05B1, 0x05FF, 1},
             {0x0600, 0x060F, 2},
             {0x0610, 0x0610, 8},
             {0x0611, 0x07BF, 2},
             {0x20A0, 0x20CF, 5}
           ]
  end

  test "reports malformed bidi rows and defaults at the failing invariant" do
    for {body, message} <- [
          {"0041; UNKNOWN\n", ~r/unknown bidi class/},
          {"0041; L; extra\n", ~r/malformed DerivedBidiClass record/},
          {"# @missing: malformed\n", ~r/malformed bidi @missing record/},
          {"# @missing: 0590..05FF; UNKNOWN\n", ~r/unsupported bidi @missing class/},
          {"# @missing: 0590..05FF; Right_To_Left\n# @missing: 05FF..0600; Arabic_Letter\n",
           ~r/overlapping Unicode ranges/}
        ] do
      input = "# DerivedBidiClass-18.0.0.txt\n# @missing: 0000..10FFFF; Left_To_Right\n" <> body
      assert_raise ArgumentError, message, fn -> Parser.bidi_classes!(input) end
    end

    assert_raise ArgumentError, ~r/malformed BidiMirroring record/, fn ->
      Parser.bidi_mirroring!("# BidiMirroring-18.0.0.txt\n003C; 003E; extra\n")
    end
  end

  test "parses reciprocal brackets and mirroring independently" do
    assert Parser.bidi_brackets!("# BidiBrackets-18.0.0.txt\n0028; 0029; o\n0029; 0028; c\n") ==
             [{0x28, 0x29, 1}, {0x29, 0x28, 2}]

    assert Parser.bidi_mirroring!("# BidiMirroring-18.0.0.txt\n003C; 003E\n003E; 003C\n") ==
             [{0x3C, 0x3E, 0}, {0x3E, 0x3C, 0}]
  end

  test "derives L3 nonspacing and enclosing marks from validated UnicodeData" do
    input =
      "0300;MARK;Mn;230;NSM;;;;;N;;;;;\n" <>
        "0488;ENCLOSING;Me;0;NSM;;;;;N;;;;;\n" <>
        "093E;SPACING;Mc;0;L;;;;;N;;;;;\n" <>
        "0CBF;VOWEL SIGN;Mn;0;L;;;;;N;;;;;\n"

    assert Parser.nonspacing_marks!(input) == [
             {0x0300, 0x0300, 1},
             {0x0488, 0x0488, 1},
             {0x0CBF, 0x0CBF, 1}
           ]
  end

  test "rejects malformed, duplicate, overlapping and mixed-version property inputs" do
    for {parser, input} <- [
          {:default_ignorables!, "# DerivedCoreProperties-17.0.0.txt\n"},
          {:default_ignorables!,
           "# DerivedCoreProperties-18.0.0.txt\n200D; Default_Ignorable_Code_Point; Yes\n"},
          {:default_ignorables!,
           "# DerivedCoreProperties-18.0.0.txt\n200D; Default_Ignorable_Code_Point\n200D; Default_Ignorable_Code_Point\n"},
          {:bidi_classes!, "# DerivedBidiClass-18.0.0.txt\n0041; UNKNOWN\n"},
          {:bidi_classes!, "# DerivedBidiClass-18.0.0.txt\n0041; L\n"},
          {:bidi_classes!,
           "# DerivedBidiClass-18.0.0.txt\n# @missing: 0000..10FFFF; Right_To_Left\n"},
          {:bidi_classes!,
           "# DerivedBidiClass-18.0.0.txt\n# @missing: 0000..10FFFF; Left_To_Right\n0041..0043; L\n0042; R\n"},
          {:bidi_brackets!, "# BidiBrackets-18.0.0.txt\n0028; 0029; o\n"},
          {:bidi_brackets!, "# BidiBrackets-18.0.0.txt\n0028; 0029; x\n"},
          {:bidi_mirroring!, "# BidiMirroring-18.0.0.txt\n003C; D800\n"},
          {:bidi_mirroring!, "# BidiMirroring-18.0.0.txt\n003C; 003E\n003C; 003E\n"}
        ] do
      assert_raise ArgumentError, fn -> apply(Parser, parser, [input]) end
    end
  end
end
