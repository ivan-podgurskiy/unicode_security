defmodule UnicodeSecurity.ConfusablesTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  doctest UnicodeSecurity

  alias UnicodeSecurity.Data.Confusables
  alias UnicodeSecurity.InvalidInputError
  alias UnicodeSecurity.Normalization
  alias UnicodeSecurity.Test.UnicodeFixtures

  test "matches independent revision 34 golden bytes on every supported runtime" do
    rows =
      "test/fixtures/golden/uts39_v34.txt"
      |> File.stream!()
      |> Stream.reject(&String.starts_with?(&1, "#"))
      |> Enum.to_list()

    for row <- rows do
      [input, expected] = row |> String.trim() |> String.split(" ; ")
      assert Base.encode16(UnicodeSecurity.skeleton(Base.decode16!(input))) == expected
    end

    assert length(rows) == 10
  end

  # Breaks: omitting revision 34's default-ignorable removal and bidi preprocessing.
  test "removes default-ignorables before assigning MA prototypes" do
    assert UnicodeSecurity.skeleton("pay\u200Dpal") == "paypal"
    assert UnicodeSecurity.skeleton("pay\u200C\uFE0F\u00ADpal") == "paypal"
    assert UnicodeSecurity.skeleton("\u034F\u061C\u{E0100}") == ""
  end

  test "matches the official revision 34 LTR-confusable sequences including L3 and L4" do
    first = "A1<\u05E9\u05C2"
    second = "\u0391\u05E9\u05BA>1"

    assert UnicodeSecurity.skeleton(first) == "Al<\u05E9\u0307"
    assert UnicodeSecurity.skeleton(second) == "Al<\u05E9\u0307"
  end

  test "resolves bidi ordering, explicit overrides and mirroring before mapping" do
    assert UnicodeSecurity.skeleton("\u05D0\u05D1") == "\u05D1\u05D0"
    assert UnicodeSecurity.skeleton("\u202Eabc(\u202C") == ")cba"
    assert UnicodeSecurity.skeleton("a\u2067\u05D0\u05D1\u2069b") == "a\u05D1\u05D0b"
  end

  test "applies X9 to boundary neutrals even when they are not default-ignorables" do
    assert UnicodeSecurity.skeleton("a\0\u{10FFFF}b") == "ab"
  end

  # Breaks: removing the Cyrillic mapping, either NFD pass, or scalar fallback;
  # accepting iodata; validating expanded intermediates as user input.
  test "returns comparison keys for ASCII, Cyrillic confusables, and mapping misses" do
    assert UnicodeSecurity.skeleton("paypal") == "paypal"
    assert UnicodeSecurity.skeleton("раypal") == "paypal"
    assert UnicodeSecurity.skeleton("m") == "rn"
    assert UnicodeSecurity.skeleton("😀\u{10FFFF}\0") == "😀"
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

  test "round-trips every pinned MA mapping and gives equivalent internalSkeleton prototypes" do
    count =
      Enum.reduce(UnicodeFixtures.confusable_rows(), 0, fn {line, source, target}, count ->
        assert Confusables.mapping(source) == String.to_charlist(target),
               "packed lookup differs at confusables.txt:#{line}"

        assert UnicodeSecurity.Confusables.internal_skeleton([source]) ==
                 UnicodeSecurity.Confusables.internal_skeleton(String.to_charlist(target)),
               "internalSkeleton conformance failed at confusables.txt:#{line}"

        count + 1
      end)

    assert count == 6712
    assert Confusables.mapping(0) == nil
    assert Confusables.mapping(0x10FFFF) == nil
  end

  test "applies bidi before mapping and does not promise public idempotence" do
    # The single ligature expands after bidi reordering. Its multi-character MA
    # prototype has a different input bidi order (revision 34's noncommutation).
    assert UnicodeSecurity.skeleton("\uFDF3") == "l\u0643\u0628\u0631"
    assert UnicodeSecurity.skeleton("l\u0643\u0628\u0631") == "l\u0631\u0628\u0643"
    assert UnicodeSecurity.skeleton("אב") == "בא"
    assert UnicodeSecurity.skeleton("בא") == "אב"
  end

  property "canonically equivalent scalar strings have equal skeletons" do
    check all(input <- scalar_string(), max_runs: 200) do
      assert UnicodeSecurity.skeleton(input) == UnicodeSecurity.skeleton(Normalization.nfd(input))
    end
  end

  property "internalSkeleton is idempotent over valid scalar strings" do
    check all(input <- scalar_string(), max_runs: 200) do
      skeleton = UnicodeSecurity.Confusables.internal_skeleton(String.to_charlist(input))
      assert UnicodeSecurity.Confusables.internal_skeleton(skeleton) == skeleton
    end
  end

  defp scalar_string do
    scalar =
      one_of([
        integer(0..0xD7FF),
        integer(0xE000..0x10FFFF),
        member_of([0x00C0, 0x006D, 0x0430, 0x0440, 0x0300, 0x0323, 0x1DF2D, 0xAC01])
      ])

    # Keep the generated inputs comfortably inside the public input domain.
    map(list_of(scalar, max_length: 32), &List.to_string/1)
  end
end
