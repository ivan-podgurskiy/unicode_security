defmodule UnicodeSecurity.JoinControlsTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.JoinControls

  # Literal outcomes derived from UTS39r34 §3.1.1.1 A1/A2/B, rather than
  # IDNA CONTEXTJ. The three language fixtures reproduce Figures 1–3.
  test "enforces the minimum exact conjunct and cursive contexts" do
    assert JoinControls.invalid_indexes([?a, 0x200D, ?b]) == [1]
    assert JoinControls.invalid_indexes([0x0628, 0x200C, 0x0627]) == []
    assert JoinControls.invalid_indexes([0x0628, 0x200C, 0x064B, 0x0627]) == [1]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200C, 0x0915]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200D, 0x093E]) == [2]
  end

  test "accepts the normative Persian Malayalam and Sinhala examples" do
    assert JoinControls.invalid_indexes([0x0646, 0x0627, 0x0645, 0x0647, 0x200C, 0x0627, 0x06CC]) ==
             []

    assert JoinControls.invalid_indexes([
             0x0D26,
             0x0D43,
             0x0D15,
             0x0D4D,
             0x200C,
             0x0D38,
             0x0D3E,
             0x0D15,
             0x0D4D,
             0x0D37,
             0x0D3F
           ]) == []

    assert JoinControls.invalid_indexes([
             0x0DC1,
             0x0DCA,
             0x200D,
             0x0DBB,
             0x0DD3,
             0x0020,
             0x0DBD,
             0x0D82,
             0x0D9A,
             0x0DCF
           ]) == []
  end

  test "rejects boundary joiners and a virama without its required letter" do
    assert JoinControls.invalid_indexes([]) == []
    assert JoinControls.invalid_indexes([?a]) == []
    assert JoinControls.invalid_indexes([0x200C, 0x200D]) == [0, 1]
    assert JoinControls.invalid_indexes([0x094D, 0x200C, 0x0915, 0x200D]) == [1, 3]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200C]) == [2]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200D]) == []
  end

  test "A1 accepts transparency on the left only and exact joining types" do
    assert JoinControls.invalid_indexes([0x0628, 0x064B, 0x0301, 0x200C, 0x0627]) == []
    assert JoinControls.invalid_indexes([0x0627, 0x200C, 0x0628]) == [1]
    assert JoinControls.invalid_indexes([0x0628, 0x200C, 0xA872]) == [1]
    assert JoinControls.invalid_indexes([0xA872, 0x200C, 0xA840]) == []
    assert JoinControls.invalid_indexes([0x0628, ?., 0x200C, 0x0627]) == [2]
  end

  test "M allows Mn CCC0 before virama but M1 excludes it on either side" do
    assert JoinControls.invalid_indexes([0x0915, 0x0902, 0x094D, 0x200C, 0x0915]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x0902, 0x200C, 0x0915]) == [3]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200C, 0x0902, 0x0915]) == [2]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x0301, 0x200C, 0x0301, 0x0915]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x093E, 0x094D, 0x200D]) == [3]
  end

  test "virama uses CCC9 including Mc independently from M and M1" do
    assert JoinControls.invalid_indexes([0x1B13, 0x1B44, 0x200C, 0x1B13]) == []
    assert JoinControls.invalid_indexes([0x1B13, 0x1B44, 0x200D]) == []
    assert JoinControls.invalid_indexes([0x1B13, 0x1B44, 0x1B44, 0x200D]) == [3]
  end

  test "overlapping viramas keep any exact regex candidate" do
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x0902, 0x094D, 0x200C, 0x0915]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x094D, 0x200D]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200C, 0x094D, 0x0915]) == []
  end

  test "B checks only the immediate dependent vowel and ends at ZWJ" do
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200D, 0x093E]) == [2]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200D, 0x0301, 0x093E]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200D, ?a]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200D, 0x200D]) == [3]
  end

  test "script restriction includes every matched scalar but excludes surrounding text" do
    assert JoinControls.invalid_indexes([?a, 0x0628, 0x200C, 0x0627, 0x0915]) == []
    assert JoinControls.invalid_indexes([0x0628, 0x200C, 0x0710]) == [1]
    assert JoinControls.invalid_indexes([0x0628, 0x05B0, 0x200C, 0x0627]) == [2]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200C, 0x0D15]) == [2]
    assert JoinControls.invalid_indexes([0x0915, 0x05B0, 0x094D, 0x200D]) == [3]
    assert JoinControls.invalid_indexes([0x0915, 0x094D, 0x200C, 0x05B0, 0x0915]) == [2]
    assert JoinControls.invalid_indexes([?a, 0x0301, 0x094D, 0x200D]) == [3]
  end

  test "NFC keeps original scalar indexes despite composition expansion and multibyte text" do
    assert JoinControls.invalid_indexes([
             0x1F600,
             ?e,
             0x0301,
             0x200D,
             0x0915,
             0x094D,
             0x200C,
             0x0915,
             0x200D,
             0x0344,
             0x200C
           ]) == [3, 8, 10]

    assert JoinControls.invalid_indexes([0x0915, 0x093C, 0x094D, 0x200C, 0x0915]) == []
    assert JoinControls.invalid_indexes([0x0915, 0x0301, 0x094D, 0x200D]) == []
  end

  test "many repeated marks and joiners preserve independent overlapping contexts" do
    input = List.duplicate(0x0301, 5000) ++ [0x200C, 0x200D]
    assert JoinControls.invalid_indexes(input) == [5000, 5001]

    cluster = [0x0915, 0x094D, 0x200C, 0x0915, 0x094D, 0x200D]
    assert JoinControls.invalid_indexes(List.duplicate(cluster, 1000) |> List.flatten()) == []
  end
end
