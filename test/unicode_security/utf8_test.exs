defmodule UnicodeSecurity.Utf8Test do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.{InvalidInputError, Utf8}

  test "decodes empty input and ASCII including NUL with byte offsets" do
    assert Utf8.decode!("") == []
    assert Utf8.decode!(<<0, ?A, 127>>) == [{0, 0}, {?A, 1}, {127, 2}]
  end

  test "decodes mixed scalar widths with byte rather than character offsets" do
    assert Utf8.decode!("Aé€😀Z") == [{?A, 0}, {0xE9, 1}, {0x20AC, 3}, {0x1F600, 6}, {?Z, 10}]
  end

  test "accepts RFC 3629 scalar boundaries including noncharacters" do
    cases = [
      {<<0xC2, 0x80>>, 0x80},
      {<<0xDF, 0xBF>>, 0x7FF},
      {<<0xE0, 0xA0, 0x80>>, 0x800},
      {<<0xED, 0x9F, 0xBF>>, 0xD7FF},
      {<<0xEE, 0x80, 0x80>>, 0xE000},
      {<<0xEF, 0xBF, 0xBF>>, 0xFFFF},
      {<<0xF0, 0x90, 0x80, 0x80>>, 0x10000},
      {<<0xF4, 0x8F, 0xBF, 0xBF>>, 0x10FFFF}
    ]

    for {encoded, scalar} <- cases do
      assert Utf8.decode!(encoded) == [{scalar, 0}]
    end
  end

  test "rejects truncated sequences at the first malformed sequence offset" do
    for bytes <- [
          <<0xC2>>,
          <<0xE0>>,
          <<0xE0, 0xA0>>,
          <<0xF0>>,
          <<0xF0, 0x90>>,
          <<0xF0, 0x90, 0x80>>
        ] do
      assert_invalid("Aé" <> bytes, 3)
    end
  end

  test "rejects stray continuation bytes and invalid lead bytes" do
    for byte <- [0x80, 0xBF, 0xF5, 0xF8, 0xFC, 0xFE, 0xFF] do
      assert_invalid(<<byte>>, 0)
      assert_invalid(<<"A", byte, 0x80>>, 1)
    end
  end

  test "rejects invalid continuation bytes in every sequence position" do
    for bytes <- [
          <<0xC2, ?A>>,
          <<0xE1, ?A, 0x80>>,
          <<0xE1, 0x80, ?A>>,
          <<0xF1, ?A, 0x80, 0x80>>,
          <<0xF1, 0x80, ?A, 0x80>>,
          <<0xF1, 0x80, 0x80, ?A>>
        ] do
      assert_invalid("é" <> bytes, 2)
    end
  end

  test "rejects overlong encodings, surrogates, and scalars above the Unicode maximum" do
    for bytes <- [
          <<0xC0, 0x80>>,
          <<0xC1, 0xBF>>,
          <<0xE0, 0x9F, 0xBF>>,
          <<0xF0, 0x8F, 0xBF, 0xBF>>,
          <<0xED, 0xA0, 0x80>>,
          <<0xED, 0xBF, 0xBF>>,
          <<0xF4, 0x90, 0x80, 0x80>>,
          <<0xF7, 0xBF, 0xBF, 0xBF>>
        ] do
      assert_invalid("A" <> bytes, 1)
    end
  end

  test "accepts exactly 4096 bytes for ASCII and multibyte scalars" do
    ascii = Utf8.decode!(:binary.copy("a", 4096))
    assert length(ascii) == 4096
    assert List.last(ascii) == {?a, 4095}

    multibyte = Utf8.decode!(:binary.copy("😀", 1024))
    assert length(multibyte) == 1024
    assert List.last(multibyte) == {0x1F600, 4092}
  end

  test "rejects 4097 bytes before attempting UTF-8 decoding" do
    for input <- [:binary.copy("a", 4097), <<0x80>> <> :binary.copy("a", 4096)] do
      error =
        assert_raise InvalidInputError, ~r/input exceeds 4096 bytes/, fn ->
          Utf8.decode!(input)
        end

      assert error.reason == :input_too_long
      assert error.byte_offset == 4096
    end
  end

  defp assert_invalid(input, offset) do
    error =
      assert_raise InvalidInputError, ~r/invalid UTF-8 at byte offset #{offset}/, fn ->
        Utf8.decode!(input)
      end

    assert error.reason == :invalid_utf8
    assert error.byte_offset == offset
  end
end
