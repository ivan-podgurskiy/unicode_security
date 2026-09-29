defmodule UnicodeSecurity.ConflictsTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.{Conflict, InvalidInputError}

  @types [:username, :tenant_slug, :organization_name]

  test "type keys preserve skeleton semantics independently of policy" do
    for type <- @types do
      assert UnicodeSecurity.conflict_key("m", type: type) == "rn"
      assert UnicodeSecurity.conflict_key("", type: type) == ""
      assert UnicodeSecurity.conflict_key("pay\u200Dpal", type: type) == "paypal"

      refute UnicodeSecurity.conflict_key("ALICE", type: type) ==
               UnicodeSecurity.conflict_key("alice", type: type)
    end
  end

  test "predicate stops without consuming a raising tail" do
    source =
      Stream.map(["rn", :tail], fn
        :tail -> raise "tail consumed"
        value -> value
      end)

    assert UnicodeSecurity.conflicts?("m", source, type: :username)

    assert_raise RuntimeError, "tail consumed", fn ->
      UnicodeSecurity.conflicts("m", source, type: :username)
    end
  end

  test "all matches preserve original indexes, duplicates and evidence" do
    hits = UnicodeSecurity.conflicts("m", ["x", "rn", "m", "rn"], type: :tenant_slug)

    assert Enum.map(hits, &{&1.index, &1.existing, &1.code}) == [
             {1, "rn", :single_script_confusable},
             {2, "m", :exact_duplicate},
             {3, "rn", :single_script_confusable}
           ]

    for hit <- hits do
      assert %Conflict{} = hit
      assert hit.input == "m" and hit.key == "rn"
      assert hit.unicode_version == UnicodeSecurity.unicode_version()
      assert hit.comparison == UnicodeSecurity.compare("m", hit.existing, type: :tenant_slug)
    end
  end

  test "canonical collision, empty duplicate and absent matches" do
    [hit] = UnicodeSecurity.conflicts("é", ["e\u0301"], type: :username)
    assert {hit.code, hit.comparison.class} == {:skeleton_collision, :none}
    assert hit.comparison.canonically_equivalent?
    assert UnicodeSecurity.conflicts?("", [""], type: :username)

    assert [%Conflict{code: :exact_duplicate, key: ""}] =
             UnicodeSecurity.conflicts("", [""], type: :username)

    refute UnicodeSecurity.conflicts?("m", ["x"], type: :username)
    assert UnicodeSecurity.conflicts("m", ["x"], type: :username) == []
  end

  test "whole and mixed script matches carry their class codes" do
    for {input, existing, code} <- [
          {"scope", "ѕсоре", :whole_script_confusable},
          {"paypal", "pаypаl", :mixed_script_confusable}
        ] do
      [hit] = UnicodeSecurity.conflicts(input, [existing], type: :organization_name)
      assert hit.code == code
      assert hit.comparison.class == code
    end
  end

  test "configuration precedes candidate and collection validation" do
    options = [
      nil,
      [],
      [type: nil],
      [type: :unknown],
      [type: :username, type: :username],
      [policy: :default],
      [type: :username, policy: :default],
      [type: :username, allowed_scripts: [:latin]],
      [unknown: true],
      %{}
    ]

    for invalid <- options do
      assert_raise ArgumentError, fn -> UnicodeSecurity.conflict_key(<<255>>, invalid) end
      assert_raise ArgumentError, fn -> UnicodeSecurity.conflicts?(<<255>>, nil, invalid) end
      assert_raise ArgumentError, fn -> UnicodeSecurity.conflicts(<<255>>, nil, invalid) end
    end

    source = Stream.map([0], fn _ -> flunk("source was enumerated") end)

    for operation <- [&UnicodeSecurity.conflicts?/3, &UnicodeSecurity.conflicts/3] do
      assert_raise InvalidInputError, fn -> operation.(<<255>>, source, type: :username) end
      assert_raise ArgumentError, fn -> operation.(nil, source, type: :username) end
      assert_raise ArgumentError, fn -> operation.("m", nil, type: :username) end
      assert operation.("m", [], type: :username) in [false, []]
      assert operation.("m", %{}, type: :username) in [false, []]
    end
  end

  test "only visited values cause predicate failures and full collection visits all" do
    assert UnicodeSecurity.conflicts?("m", ["rn", <<255>>], type: :username)

    for operation <- [&UnicodeSecurity.conflicts?/3, &UnicodeSecurity.conflicts/3] do
      for value <- [nil, {"rn", 1}] do
        assert_raise ArgumentError, fn -> operation.("m", [value], type: :username) end
      end

      error =
        assert_raise InvalidInputError, fn ->
          operation.("m", ["é" <> <<255>>], type: :username)
        end

      assert {error.reason, error.byte_offset} == {:invalid_utf8, 2}

      error =
        assert_raise InvalidInputError, fn ->
          operation.("m", [String.duplicate("a", 4097)], type: :username)
        end

      assert {error.reason, error.byte_offset} == {:input_too_long, 4096}
    end

    assert_raise InvalidInputError, fn ->
      UnicodeSecurity.conflicts("m", ["rn", <<255>>], type: :username)
    end
  end

  test "candidate limits and enumerable errors propagate" do
    for input <- ["é" <> <<255>>, String.duplicate("a", 4097)] do
      assert_raise InvalidInputError, fn ->
        UnicodeSecurity.conflict_key(input, type: :username)
      end

      assert_raise InvalidInputError, fn ->
        UnicodeSecurity.conflicts?(input, [], type: :username)
      end

      assert_raise InvalidInputError, fn ->
        UnicodeSecurity.conflicts(input, [], type: :username)
      end
    end

    source = Stream.map([0], fn _ -> raise "enumeration failed" end)

    assert_raise RuntimeError, "enumeration failed", fn ->
      UnicodeSecurity.conflicts?("m", source, type: :username)
    end

    assert_raise RuntimeError, "enumeration failed", fn ->
      UnicodeSecurity.conflicts("m", source, type: :username)
    end
  end

  test "finite streams retain indexes and repeated matches" do
    source = Stream.map(["x", "rn", "m", "rn"], & &1)
    assert UnicodeSecurity.conflicts?("m", source, type: :username)

    assert Enum.map(UnicodeSecurity.conflicts("m", source, type: :username), & &1.index) == [
             1,
             2,
             3
           ]
  end

  property "predicate agrees with collection and public keys on finite valid lists" do
    check all(
            input <- member_of(["", "m", "rn", "é", "e\u0301", "alice", "bob"]),
            values <-
              list_of(member_of(["", "m", "rn", "é", "e\u0301", "alice", "bob"]), max_length: 12),
            max_runs: 40
          ) do
      key = UnicodeSecurity.conflict_key(input, type: :username)

      expected_indexes =
        values
        |> Enum.with_index()
        |> Enum.filter(fn {value, _index} ->
          UnicodeSecurity.conflict_key(value, type: :username) == key
        end)
        |> Enum.map(&elem(&1, 1))

      hits = UnicodeSecurity.conflicts(input, values, type: :username)
      assert Enum.map(hits, & &1.index) == expected_indexes
      assert UnicodeSecurity.conflicts?(input, values, type: :username) == (hits != [])
    end
  end
end
