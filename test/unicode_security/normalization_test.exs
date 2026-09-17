defmodule UnicodeSecurity.NormalizationTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.{InvalidInputError, Normalization}
  alias UnicodeSecurity.Test.UnicodeFixtures

  for {name, input} <- [
        {"nil", nil},
        {"an integer", 42},
        {"a charlist", [65, 233]},
        {"a non-byte-aligned bitstring", <<1::1>>}
      ] do
    test "rejects #{name} with ArgumentError" do
      assert_raise ArgumentError, fn -> Normalization.nfd(unquote(Macro.escape(input))) end
    end
  end

  test "satisfies all five NFD invariants for every official normalization row" do
    rows =
      Enum.reduce(UnicodeFixtures.normalization_rows(), 0, fn {line, [c1, c2, c3, c4, c5]},
                                                              count ->
        for {source, expected, column} <- [
              {c1, c3, 1},
              {c2, c3, 2},
              {c3, c3, 3},
              {c4, c5, 4},
              {c5, c5, 5}
            ] do
          assert Normalization.nfd(source) == expected,
                 "NFD conformance failed at NormalizationTest.txt:#{line}, column #{column}"
        end

        count + 1
      end)

    # Prevent an empty or partially parsed corpus from silently passing conformance.
    assert rows == 20_171
  end

  test "composes canonical pairs and Hangul from decoded scalars" do
    assert Normalization.nfc_scalars([?e, 0x301]) == [0xE9]
    assert Normalization.nfc_scalars([0x1100, 0x1161, 0x11A8]) == [0xAC01]
  end

  test "satisfies every official NFC invariant" do
    rows =
      Enum.reduce(UnicodeFixtures.normalization_rows(), 0, fn {line, [c1, c2, c3, c4, c5]},
                                                              count ->
        for {source, expected} <- [{c1, c2}, {c2, c2}, {c3, c2}, {c4, c4}, {c5, c4}] do
          assert Normalization.nfc_scalars(scalars(source)) == scalars(expected),
                 "NFC conformance failed at line #{line}"
        end

        count + 1
      end)

    assert rows == 20_171
  end

  test "honors blocking, exclusions, leading marks, and original-input-only limits" do
    assert Normalization.nfc_scalars([]) == []
    assert Normalization.nfc_scalars([0x301, 0x323, ?q]) == [0x323, 0x301, ?q]
    assert Normalization.nfc_scalars([?A, 0x305, 0x301]) == [?A, 0x305, 0x301]
    assert Normalization.nfc_scalars([?A, 0x323, 0x301]) == [0x1EA0, 0x301]
    assert Normalization.nfc_scalars([0x915, 0x93C]) == [0x915, 0x93C]
    assert Normalization.nfc_scalars([0x1D157, 0x1D165]) == [0x1D157, 0x1D165]
    assert Normalization.nfc_scalars([0x1100, 0x301, 0x1161]) == [0x1100, 0x301, 0x1161]
    assert Normalization.nfc_scalars(List.duplicate(?a, 4097)) == List.duplicate(?a, 4097)
  end

  defp scalars(binary), do: for(<<scalar::utf8 <- binary>>, do: scalar)

  test "matches the checked-in golden bytes across OTP versions" do
    actual =
      UnicodeFixtures.golden_corpus()
      |> Enum.map(fn input -> {input, Normalization.nfd(input)} end)
      |> :erlang.term_to_binary()

    assert actual == File.read!(Path.expand("../fixtures/golden/milestone_0.term", __DIR__))
  end

  test "preserves empty input, ASCII, and undecomposable non-BMP scalars" do
    for input <- ["", "Hello\0World!", "😀\u{10FFFF}"] do
      assert Normalization.nfd(input) == input
    end
  end

  test "recursively expands canonical mappings without compatibility decomposition" do
    for {input, expected} <- [
          {"À", "A\u0300"},
          {"Ǻ", "A\u030A\u0301"},
          {"Å", "A\u030A"},
          {"ﬁ①", "ﬁ①"},
          {"\u{1D15E}", "\u{1D157}\u{1D165}"}
        ] do
      assert Normalization.nfd(input) == expected
      assert Normalization.nfd(expected) == expected
    end
  end

  test "decomposes Hangul syllables with and without a trailing consonant" do
    for {input, expected} <- [
          {"가", "가"},
          {"각", "각"},
          {"힣", "힣"},
          {"\uABFF\uD7A4", "\uABFF\uD7A4"}
        ] do
      assert Normalization.nfd(input) == expected
    end
  end

  test "reorders non-starters stably and never across a starter" do
    assert Normalization.nfd("q\u0307\u0323") == "q\u0323\u0307"
    assert Normalization.nfd("q\u0307\u0301\u0323") == "q\u0323\u0307\u0301"
    assert Normalization.nfd("\u0307\u0323q\u0301\u0323") == "\u0323\u0307q\u0323\u0301"
    assert Normalization.nfd("q\u0307a\u0323") == "q\u0307a\u0323"
  end

  test "orders marks introduced by decomposition together with adjacent marks" do
    assert Normalization.nfd("Ḋ\u0323") == "D\u0323\u0307"
    assert Normalization.nfd("\u0344\u0323") == "\u0323\u0308\u0301"
  end

  test "allows normalized output to expand beyond the input byte limit" do
    assert Normalization.nfd(:binary.copy("À", 2048)) == :binary.copy("A\u0300", 2048)
  end

  test "rejects invalid UTF-8 and oversized inputs with decoder diagnostics" do
    invalid = assert_raise InvalidInputError, fn -> Normalization.nfd(<<"é", 0x80>>) end
    assert invalid.reason == :invalid_utf8
    assert invalid.byte_offset == 2

    oversized =
      assert_raise InvalidInputError, fn -> Normalization.nfd(:binary.copy("a", 4097)) end

    assert oversized.reason == :input_too_long
    assert oversized.byte_offset == 4096
  end
end
