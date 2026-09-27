defmodule UnicodeSecurity.IdnaParserTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.IdnaParser

  test "parses closed statuses, comments, blank mappings, ranges, and optional markers" do
    text = """
    # header
    0000..0040 ; valid ; ; NV8 # metadata
    0041 ; mapped ; 0061
    0042 ; ignored # no mapping
    0043 ; deviation ; 0063 0064 ; XV8
    0044..10FFFF ; disallowed
    """

    assert IdnaParser.parse!(text) == [
             {0, 0x40, :valid, []},
             {0x41, 0x41, :mapped, [0x61]},
             {0x42, 0x42, :ignored, []},
             {0x43, 0x43, :deviation, [0x63, 0x64]},
             {0x44, 0x10FFFF, :disallowed, []}
           ]
  end

  test "rejects unknown status without creating an atom" do
    assert_raise ArgumentError, fn ->
      IdnaParser.parse!("0000..10FFFF ; unexpected ; 0061\n")
    end
  end

  test "rejects malformed payloads and metadata" do
    for row <- [
          "0000..10FFFF ; mapped",
          "0000..10FFFF ; ignored ; 0061",
          "0000..10FFFF ; mapped ; ZZ",
          "0000..10FFFF ; mapped ; D800",
          "0000..10FFFF ; mapped ; 110000",
          "0000..10FFFF ; mapped ; 0061 0061 ; bogus",
          "0000..10FFFF ; mapped ; 0061 ; NV8 ; extra",
          "0000..10FFFF ; mapped ; 0061  ; ; 0062"
        ] do
      assert_raise ArgumentError, fn -> IdnaParser.parse!(row <> "\n") end
    end
  end

  test "rejects unsorted, overlapping, and incomplete ranges" do
    for text <- [
          "0001..10FFFF ; valid\n0000 ; valid\n",
          "0000..0002 ; valid\n0002..10FFFF ; valid\n",
          "0000 ; valid\n0002..10FFFF ; valid\n",
          "0000..10FFFE ; valid\n",
          "0000..110000 ; valid\n",
          "0000..0001 ; valid\n0003..0002 ; valid\n0003..10FFFF ; valid\n"
        ] do
      assert_raise ArgumentError, fn -> IdnaParser.parse!(text) end
    end
  end
end
