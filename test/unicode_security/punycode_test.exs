defmodule UnicodeSecurity.Idna.PunycodeTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.Idna.Punycode

  test "matches literal RFC 3492 encodings and preserves basic case" do
    for {unicode, ascii} <- [
          {"bücher", "bcher-kva"},
          {"mañana", "maana-pta"},
          {"例え", "r8jz45g"},
          {"他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"},
          {"Pročprostěnemluvíčesky", "Proprostnemluvesky-uyb24dma41a"},
          {"-> $1.00 <-", "-> $1.00 <--"}
        ] do
      scalars = String.to_charlist(unicode)
      assert Punycode.encode(scalars, 1024) == {:ok, ascii}
      assert Punycode.decode(ascii, 1024) == {:ok, scalars}
    end
  end

  test "handles empty and all-basic bodies with the RFC delimiter" do
    assert Punycode.encode([], 0) == {:ok, ""}
    assert Punycode.decode("", 0) == {:ok, []}
    assert Punycode.encode([0, ?A, ?-, 127], 5) == {:ok, <<0, ?A, ?-, 127, ?->>}
    assert Punycode.decode(<<0, ?A, ?-, 127, ?->>, 4) == {:ok, [0, ?A, ?-, 127]}
    assert Punycode.decode("a--", 2) == {:ok, [?a, ?-]}
    assert Punycode.encode([?-], 2) == {:ok, "--"}
    assert Punycode.decode("--", 1) == {:ok, [?-]}
  end

  test "uses the last delimiter and accepts uppercase encoded digits" do
    assert Punycode.decode("bcher-KvA", 6) == {:ok, String.to_charlist("bücher")}
    assert Punycode.decode("Bcher-kva", 6) == {:ok, String.to_charlist("Bücher")}
    assert Punycode.decode("a--cja", 3) == {:ok, [?a, ?-, 0xE9]}
    assert Punycode.encode([?a, ?-, 0xE9], 6) == {:ok, "a--cja"}
  end

  test "matches independent scalar boundary encodings" do
    # Literal bodies independently checked with Python's RFC 3492 codec.
    for {scalars, ascii} <- [
          {[0x80], "a"},
          {[0x81], "ba"},
          {[0xD7FF], "hb9b"},
          {[0xE000], "0y0c"},
          {[0x1F600], "e28h"},
          {[0x10FFFF], "dn32g"},
          {[0x10FFFF, 0x10FFFF], "dn32ga"},
          {[?a, 0x10FFFF], "a-h023p"},
          {[0x10FFFF, ?a], "a-g023p"}
        ] do
      assert Punycode.encode(scalars, byte_size(ascii)) == {:ok, ascii}
      assert Punycode.decode(ascii, length(scalars)) == {:ok, scalars}
    end
  end

  test "accepts a zero terminal digit even when its unused weight exceeds the scalar bound" do
    scalars = [0x10FFFF] ++ List.duplicate(?a, 200) ++ [0x10FFFF]
    ascii = String.duplicate("a", 200) <> "-if8983pzfa"
    assert Punycode.encode(scalars, 211) == {:ok, ascii}
    assert Punycode.decode(ascii, 202) == {:ok, scalars}
  end

  test "carries the post-emission scan remainder before the maximum scalar" do
    scalars = [0x10FFFE] ++ List.duplicate(?a, 200) ++ [0x10FFFF]
    # Independent Python RFC 3492 codec result; the valid body is 211 bytes.
    ascii = String.duplicate("a", 200) <> "-r87983prla"

    assert byte_size(ascii) == 211
    assert Punycode.encode(scalars, 1024) == {:ok, ascii}
    assert Punycode.decode(ascii, 202) == {:ok, scalars}
  end

  test "carries high-scalar remainders across positions and repetitions" do
    basics = List.duplicate(?a, 200)
    prefix = String.duplicate("a", 200)

    for {scalars, suffix} <- [
          {[0x10FFFF] ++ basics ++ [0x10FFFE], "-hf8983pba"},
          {[0x10FFFE, 0x10FFFF] ++ basics, "-r87983p1fa"},
          {[0x10FFFE] ++ basics ++ [0x10FFFF, 0x10FFFE, 0x10FFFF], "-r87983pzfauhb"}
        ] do
      ascii = prefix <> suffix
      assert Punycode.encode(scalars, 1024) == {:ok, ascii}
      assert Punycode.decode(ascii, length(scalars)) == {:ok, scalars}
    end
  end

  test "rejects non-scalars at either interface" do
    for scalar <- [-1, 0xD800, 0xDFFF, 0x110000] do
      assert Punycode.encode([scalar], 59) == {:error, :invalid_scalar}
    end

    assert Punycode.decode("ib9b", 63) == {:error, :invalid_scalar}
    assert Punycode.decode("zy0c", 63) == {:error, :invalid_scalar}
  end

  test "rejects invalid prefixes, digits, and truncated continuations" do
    for ascii <- ["é", "é-a", <<0xFF>>, "!", "a-!", "_", "b", "z", "-", "-a"] do
      assert Punycode.decode(ascii, 63) == {:error, :invalid_encoding}
    end
  end

  test "stops before exceeding the exact output byte budget" do
    assert Punycode.encode(String.to_charlist("bücher"), 9) == {:ok, "bcher-kva"}
    assert Punycode.encode(String.to_charlist("bücher"), 8) == {:error, :output_too_long}
    assert Punycode.encode([?a], 1) == {:error, :output_too_long}
    assert Punycode.encode([0x80], 0) == {:error, :output_too_long}
    assert Punycode.encode([0x10FFFF], 4) == {:error, :output_too_long}
    assert Punycode.encode(List.duplicate(0x80, 64), 63) == {:error, :output_too_long}
  end

  test "stops before exceeding the exact output scalar budget" do
    assert Punycode.decode("bcher-kva", 6) == {:ok, String.to_charlist("bücher")}
    assert Punycode.decode("bcher-kva", 5) == {:error, :output_too_long}
    assert Punycode.decode("abc-", 2) == {:error, :output_too_long}
    assert Punycode.decode("a", 0) == {:error, :output_too_long}
    assert Punycode.decode("aa", 1) == {:error, :output_too_long}
  end

  test "rejects out-of-range arithmetic and long continuation bodies without crashing" do
    assert Punycode.decode("en32g", 63) == {:error, :overflow}

    for size <- [63, 1024, 4096] do
      assert Punycode.decode(String.duplicate("9", size), 63) == {:error, :overflow}
      assert {:error, reason} = Punycode.decode(String.duplicate("z", size), 63)
      assert reason in [:invalid_scalar, :overflow]
    end

    # A positive digit requires an out-of-bound weight after the second insertion's "zf".
    ascii = String.duplicate("a", 200) <> "-if8983pzfb"
    assert Punycode.decode(ascii, 202) == {:error, :overflow}
  end

  test "preserves invalid and truncated input errors in the bounded weight terminal path" do
    prefix = String.duplicate("a", 200) <> "-if8983pzf"
    assert Punycode.decode(prefix, 202) == {:error, :invalid_encoding}
    assert Punycode.decode(prefix <> "!", 202) == {:error, :invalid_encoding}

    assert Punycode.decode(prefix <> "A", 202) ==
             {:ok, [0x10FFFF] ++ List.duplicate(?a, 200) ++ [0x10FFFF]}
  end

  property "round trips scalar lists including supplementary and repeated scalars" do
    scalar = one_of([integer(0..0xD7FF), integer(0xE000..0x10FFFF)])

    check all(scalars <- list_of(scalar, max_length: 64), max_runs: 200) do
      assert {:ok, ascii} = Punycode.encode(scalars, 1024)
      assert Punycode.decode(ascii, 64) == {:ok, scalars}
    end
  end
end
