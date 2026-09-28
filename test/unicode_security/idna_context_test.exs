defmodule UnicodeSecurity.IdnaContextTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Idna.{Bidi, ContextJ}

  test "CONTEXTJ uses an immediate virama for both joiners" do
    assert ContextJ.invalid_indexes([0x915, 0x94D, 0x200D]) == []
    assert ContextJ.invalid_indexes([0x915, 0x94D, 0x200C]) == []
    assert ContextJ.invalid_indexes([0x915, 0x94D, 0x301, 0x200D]) == [3]
    assert ContextJ.invalid_indexes([0x915, 0x94D, 0x301, 0x200C]) == [3]
    assert ContextJ.invalid_indexes([0x200D, 0x200C]) == [0, 1]
  end

  test "CONTEXTJ ZWNJ uses nearest nontransparent joining types on both sides" do
    assert ContextJ.invalid_indexes([0x628, 0x64E, 0x200C, 0x64E, 0x628]) == []
    assert ContextJ.invalid_indexes([0x628, 0x200C, 0x628]) == []
    assert ContextJ.invalid_indexes([?a, 0x200C, ?b]) == [1]
    assert ContextJ.invalid_indexes([0x200C, 0x628, 0x628, 0x200C]) == [0, 3]
    assert ContextJ.invalid_indexes([0x628, 0x200C, ?a, 0x200C, 0x628]) == [1, 3]
  end

  test "bidi activates for the whole domain, including numeric leading LTR labels" do
    assert Bidi.invalid_indexes([String.to_charlist("1a"), String.to_charlist("a")]) == []
    assert {0, 0, :first} in Bidi.invalid_indexes([String.to_charlist("1a"), [0x5D0]])
    assert Bidi.invalid_indexes([[?a, ?1], [0x5D0], nil, []]) == []
  end

  test "bidi accepts all permitted internal classes and NSM suffixes" do
    for scalar <- [?a, ?1, ?+, ?$, ?,, ?@, 0x200C, 0x301] do
      assert Bidi.invalid_indexes([[?a, scalar, ?a], [0x5D0]]) == []
    end

    for scalar <- [0x5D0, 0x628, 0x661, ?1, ?+, ?$, ?,, ?@, 0x200C, 0x301] do
      assert Bidi.invalid_indexes([[0x5D0, scalar, 0x5D0]]) == []
    end

    assert Bidi.invalid_indexes([[?a, ?1, 0x301], [0x5D0, 0x661, 0x301]]) == []
  end

  test "bidi reports each forbidden class and independent first and last failures" do
    for scalar <- [0x5D0, 0x628, 0x661, ?\s, ?\n, ?\t, 0x202A] do
      assert {0, 1, :allowed} in Bidi.invalid_indexes([[?a, scalar, ?a], [0x5D0]])
    end

    for scalar <- [?a, ?\s, ?\n, ?\t, 0x202A] do
      assert {0, 1, :allowed} in Bidi.invalid_indexes([[0x5D0, scalar, 0x5D0]])
    end

    assert {0, 0, :first} in Bidi.invalid_indexes([[?1, 0x5D0]])
    assert {0, 1, :last} in Bidi.invalid_indexes([[?a, ?+, 0x301], [0x5D0]])
    assert {0, 1, :last} in Bidi.invalid_indexes([[0x5D0, ?+, 0x301]])
    assert {0, 1, :allowed} in Bidi.invalid_indexes([[?a, 0x661]])
    assert {0, 1, :last} in Bidi.invalid_indexes([[?a, 0x661]])

    assert Bidi.invalid_indexes([[?1, ?\s, ?+], [0x5D0]]) ==
             [{0, 0, :first}, {0, 1, :allowed}, {0, 2, :last}]
  end

  test "bidi reports mixed RTL digits once and skips undecoded and empty labels" do
    assert Bidi.invalid_indexes([[0x5D0, ?1, 0x661, ?2, 0x662], nil, []]) ==
             [{0, nil, :mixed_digits}]

    assert Bidi.invalid_indexes([nil, [], String.to_charlist("abc")]) == []
  end
end
