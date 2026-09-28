defmodule UnicodeSecurity.IdnaTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Idna

  test "nontransitional mapping and equivalent A-labels" do
    assert Idna.to_unicode(String.to_charlist("BÜCHER。example")) ==
             {:ok, String.to_charlist("bücher.example")}

    assert Idna.to_ascii(String.to_charlist("bücher.example")) ==
             {:ok, String.to_charlist("xn--bcher-kva.example")}

    assert Idna.to_unicode(String.to_charlist("xn--fa-hia.de")) ==
             {:ok, String.to_charlist("faß.de")}

    assert Idna.to_unicode(String.to_charlist("a.\u00AD")) == {:ok, [?a, ?.]}
  end

  test "failed A-label never gets remapped into validity" do
    assert {:error, issues} = Idna.to_unicode(String.to_charlist("xn--u-ccb.a"))

    assert Enum.any?(
             issues,
             &(&1.code == :domain_idna_disallowed and &1.details.rule == :not_nfc)
           )

    assert {:error, _} = Idna.to_unicode(String.to_charlist("xn--abc-.a"))
    assert {:error, _} = Idna.to_unicode([0xD800, ?., ?a])
  end

  test "ASCII DNS boundaries and Unicode mode is not DNS limited" do
    assert {:ok, _} = Idna.to_ascii(List.duplicate(?a, 63))
    assert {:error, _} = Idna.to_ascii(List.duplicate(?a, 64))

    name253 =
      Enum.join(
        [
          String.duplicate("a", 63),
          String.duplicate("b", 63),
          String.duplicate("c", 63),
          String.duplicate("d", 61)
        ],
        "."
      )

    assert byte_size(name253) == 253
    assert Idna.to_ascii(String.to_charlist(name253)) == {:ok, String.to_charlist(name253)}
    assert {:error, _} = Idna.to_ascii(String.to_charlist(name253 <> "e"))

    assert Idna.to_unicode(String.to_charlist(String.duplicate("a", 64))) ==
             {:ok, List.duplicate(?a, 64)}

    assert {:ok, punycode63} = Idna.to_ascii(List.duplicate(?a, 55) ++ [0x00E9])
    assert length(punycode63) == 63
    assert {:error, issues} = Idna.to_ascii(List.duplicate(?a, 56) ++ [0x00E9])
    assert Enum.any?(issues, &(&1.code == :domain_label_too_long))
  end

  test "separators, empty labels, and contextual bidi" do
    for separator <- [?., 0x3002, 0xFF0E, 0xFF61] do
      assert Idna.to_unicode([?a, separator, ?b]) == {:ok, ~c"a.b"}
    end

    assert {:error, _} = Idna.to_unicode(~c".a")
    assert {:error, _} = Idna.to_unicode(~c"a..b")
    assert {:ok, ~c"a."} = Idna.to_unicode([?a, ?., 0x00AD])
    assert {:error, _} = Idna.to_ascii(~c"a.")
    assert {:error, _} = Idna.to_ascii([?a, ?., 0x00AD])
    assert Idna.process_tagged(Enum.with_index(~c"a."), :hostname).ascii == "a."
    assert Idna.process_tagged(Enum.with_index([?a, ?., 0x00AD]), :hostname).ascii == "a."
    refute Idna.process_tagged(Enum.with_index(~c"."), :hostname).valid?
    assert {:error, _} = Idna.to_unicode(String.to_charlist("1a.א"))
    assert {:ok, ~c"1a.a"} = Idna.to_unicode(~c"1a.a")
    assert {:ok, _} = Idna.to_ascii(String.to_charlist("¢.example"))
  end

  test "partial label facts retain valid neighbors and source origins" do
    report = Idna.process_tagged([{?a, 4}, {?., 5}, {0xD800, 6}, {?., 7}, {?b, 8}], :ascii)
    refute report.valid?
    assert Enum.at(report.labels, 0).ascii == "a"
    assert Enum.at(report.labels, 2).ascii == "b"
    assert Enum.any?(report.issues, &(&1.origin == 6 and &1.details.rule == :invalid_scalar))

    leading_mark = Idna.process_tagged([{0x00AD, 11}, {0x0308, 12}, {?., 13}, {?a, 14}], :unicode)
    assert Enum.any?(leading_mark.issues, &(&1.origin == 12 and &1.details.rule == :leading_mark))
    assert Enum.at(leading_mark.labels, 1).unicode == [?a]
  end
end
