defmodule UnicodeSecurity.IdnaFixturesTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Test.IdnaFixtures

  test "blank inheritance differs from explicit emptiness" do
    [row] = IdnaFixtures.parse!(~S(a; ""; [V1]; ; []; ;))
    assert row.source == [?a]
    assert row.unicode == []
    assert row.unicode_status == ["V1"]
    assert row.ascii == []
    assert row.ascii_status == []
  end

  test "surrogates and non-BMP escapes remain integer input" do
    [surrogate, non_bmp] = IdnaFixtures.parse!(~S(\uD800; ; [V7]; ; [A3]; ;
\x{1F600}; ; ; ; ; ;))
    assert surrogate.source == [0xD800]
    assert non_bmp.source == [0x1F600]
  end

  test "malformed columns and escapes report fixture line" do
    assert_raise ArgumentError, ~r/line 2/, fn -> IdnaFixtures.parse!("# header\na; b") end
    assert_raise ArgumentError, ~r/line 1/, fn -> IdnaFixtures.parse!(~S(\uZZZZ; ; ; ; ; ;)) end
  end
end
