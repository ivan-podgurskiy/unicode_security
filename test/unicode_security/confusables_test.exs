defmodule UnicodeSecurity.ConfusablesTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.{InvalidInputError, Normalization}
  alias UnicodeSecurity.Data.Confusables
  alias UnicodeSecurity.Test.UnicodeFixtures

  # Breaks: removing the Cyrillic mapping, either NFD pass, or scalar fallback;
  # accepting iodata; validating expanded intermediates as user input.
  test "returns comparison keys for ASCII, Cyrillic confusables, and mapping misses" do
    assert UnicodeSecurity.skeleton("paypal") == "paypal"
    assert UnicodeSecurity.skeleton("раypal") == "paypal"
    assert UnicodeSecurity.skeleton("m") == "rn"
    assert UnicodeSecurity.skeleton("😀\u{10FFFF}\0") == "😀\u{10FFFF}\0"
    assert UnicodeSecurity.skeleton("") == ""
  end

  test "normalizes canonically equivalent input before mapping" do
    assert UnicodeSecurity.skeleton("À") == "A\u0300"
    assert UnicodeSecurity.skeleton("À") == UnicodeSecurity.skeleton("A\u0300")
    # NFD must expose the cedilla before the cedilla-to-comma-below mapping.
    assert UnicodeSecurity.skeleton("Ç") == "C\u0326"
  end

  test "orders newly assigned combining marks using pinned data rather than host Unicode" do
    assert UnicodeSecurity.skeleton("q\u{1E6E3}\u0323") == "q\u0323\u{1E6E3}"
  end

  test "normalizes and orders combining marks introduced by a mapping" do
    assert UnicodeSecurity.skeleton("\u{1DF2D}") == "d\u0326\u0314"
  end

  test "allows NFD and confusable expansions beyond the original input byte limit" do
    assert UnicodeSecurity.skeleton(:binary.copy("À", 2048)) == :binary.copy("A\u0300", 2048)
    assert UnicodeSecurity.skeleton(:binary.copy("m", 4096)) == :binary.copy("rn", 4096)
  end

  test "rejects all nonbinary input with ArgumentError" do
    for input <- [["paypal"], ~c"paypal", nil, 123, <<1::1>>] do
      assert_raise ArgumentError, fn -> UnicodeSecurity.skeleton(input) end
    end
  end

  test "preserves malformed input and size-limit diagnostics" do
    for {input, offset} <- [{<<0xFF>>, 0}, {<<"é", 0x80>>, 2}, {<<0xED, 0xA0, 0x80>>, 0}] do
      error = assert_raise InvalidInputError, fn -> UnicodeSecurity.skeleton(input) end
      assert error.reason == :invalid_utf8
      assert error.byte_offset == offset
    end

    error =
      assert_raise InvalidInputError, fn -> UnicodeSecurity.skeleton(:binary.copy("a", 4097)) end

    assert error.reason == :input_too_long
    assert error.byte_offset == 4096
  end

  test "round-trips every pinned MA mapping and gives equivalent source and target skeletons" do
    count =
      Enum.reduce(UnicodeFixtures.confusable_rows(), 0, fn {line, source, target}, count ->
        assert Confusables.mapping(source) == String.to_charlist(target),
               "packed lookup differs at confusables.txt:#{line}"

        assert UnicodeSecurity.skeleton(<<source::utf8>>) == UnicodeSecurity.skeleton(target),
               "skeleton conformance failed at confusables.txt:#{line}"

        count + 1
      end)

    assert count == 6712
    assert Confusables.mapping(0) == nil
    assert Confusables.mapping(0x10FFFF) == nil
  end

  property "canonically equivalent scalar strings have equal skeletons" do
    check all(input <- scalar_string(), max_runs: 200) do
      assert UnicodeSecurity.skeleton(input) == UnicodeSecurity.skeleton(Normalization.nfd(input))
    end
  end

  property "skeletons are idempotent over valid scalar strings" do
    check all(input <- scalar_string(), max_runs: 200) do
      skeleton = UnicodeSecurity.skeleton(input)
      assert UnicodeSecurity.skeleton(skeleton) == skeleton
    end
  end

  defp scalar_string do
    scalar =
      one_of([
        integer(0..0xD7FF),
        integer(0xE000..0x10FFFF),
        member_of([0x00C0, 0x006D, 0x0430, 0x0440, 0x0300, 0x0323, 0x1DF2D, 0xAC01])
      ])

    # 32 scalars also keep the largest possible skeleton expansion within the
    # public 4,096-byte domain for the second call in the idempotence property.
    map(list_of(scalar, max_length: 32), &List.to_string/1)
  end
end
