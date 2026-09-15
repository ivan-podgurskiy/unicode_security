defmodule UnicodeSecurity.BidiTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Bidi
  alias UnicodeSecurity.Test.BidiFixtures

  @moduletag timeout: 180_000

  test "PDF inside an overflowing isolate cannot terminate the surrounding embedding" do
    input = List.duplicate(0x202B, 63) ++ [0x2067, 0x202C, 0x05D0, 0x2069, 0x05D1, 0x202C, 0x63]
    result = Bidi.resolve(input, 0)
    assert Enum.take(result.levels, 63) == List.duplicate(:x, 63)
    assert Enum.drop(result.levels, 63) == [125, :x, 125, 125, 125, :x, 124]
    assert result.order == [67, 66, 65, 63, 69]
  end

  test "uses P1 paragraph boundaries and one line per paragraph without layout wrapping" do
    assert Bidi.reorder(~c"אב\n") == ~c"בא\n"
    assert Bidi.reorder(~c"אב\n\nגד\n") == ~c"בא\n\nדג\n"
    # U+2028 is WS, not B. With no display layout, its RTL context is preserved.
    assert Bidi.reorder(~c"אב\u2028גד") == ~c"דג\u2028בא"
  end

  test "resolves all pinned bidi class conformance cases through L2" do
    count =
      Enum.reduce(BidiFixtures.type_rows(), 0, fn {line, scalars, directions, levels, order},
                                                  count ->
        for direction <- directions do
          result = Bidi.resolve(scalars, direction)

          assert result.levels == levels,
                 "BidiTest.txt:#{line} #{inspect(direction)} levels: #{inspect(result.levels)} != #{inspect(levels)}"

          assert result.order == order, "BidiTest.txt:#{line} #{inspect(direction)} order"
        end

        count + 1
      end)

    assert count == 490_846
  end

  test "resolves all pinned character and paired-bracket conformance cases through L2" do
    count =
      Enum.reduce(BidiFixtures.character_rows(), 0, fn {line, scalars, direction, paragraph,
                                                        levels, order},
                                                       count ->
        result = Bidi.resolve(scalars, direction)
        assert result.paragraph_level == paragraph, "BidiCharacterTest.txt:#{line} paragraph"

        assert result.levels == levels,
               "BidiCharacterTest.txt:#{line} levels: #{inspect(result.levels)} != #{inspect(levels)}"

        assert result.order == order, "BidiCharacterTest.txt:#{line} order"
        count + 1
      end)

    assert count == 91_707
  end

  test "splits paragraphs and preserves combining clusters while mirroring odd levels" do
    assert Bidi.reorder(~c"A1<שׂ") == ~c"A1<שׂ"
    assert Bidi.reorder(~c"Αשֺ>1") == ~c"Α1<שֺ"
    assert Bidi.reorder(~c"אב\nגד") == ~c"בא\nדג"

    assert Bidi.reorder([0x202E, 0x61, 0x300, 0x301, 0x2140, 0x202C]) ==
             [0x2140, 0x61, 0x300, 0x301]

    assert Bidi.reorder([]) == []
  end
end
