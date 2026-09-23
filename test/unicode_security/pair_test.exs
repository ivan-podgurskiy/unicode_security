defmodule UnicodeSecurity.PairTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.{ComparisonOptions, InvalidInputError, Pair, Scripts}

  test "key equality does not call canonical equality a confusable" do
    assert UnicodeSecurity.same_skeleton?("m", "rn")
    assert UnicodeSecurity.confusable?("m", "rn")
    assert UnicodeSecurity.same_skeleton?("é", "e\u0301")
    refute UnicodeSecurity.confusable?("é", "e\u0301")
    assert UnicodeSecurity.same_skeleton?("", "")
    refute UnicodeSecurity.confusable?("", "")
    refute UnicodeSecurity.same_skeleton?("alice", "bob")
  end

  test "comparison exposes complete facts without conflating canonical identity" do
    pair = UnicodeSecurity.compare("m", "rn", type: :tenant_slug)
    assert Pair.compare("m", "rn") == UnicodeSecurity.compare("m", "rn")
    assert pair.confusable? and pair.same_skeleton?
    refute pair.canonically_equivalent?
    assert pair.class == :single_script_confusable
    assert pair.left_resolved_scripts == [:hntl, :latin]

    assert Enum.map(pair.mappings, &{&1.side, &1.codepoint_index, &1.mapping}) ==
             [{:left, 0, "rn"}, {:right, 0, "r"}, {:right, 1, "n"}]

    canonical = UnicodeSecurity.compare("é", "e\u0301")
    assert canonical.canonically_equivalent? and canonical.same_skeleton?
    refute canonical.confusable?
    assert canonical.class == :none
    assert length(canonical.mappings) == 3
  end

  test "public comparison covers all classes, neutral sets, and unequal evidence" do
    for {left, right, class} <- [
          {"m", "rn", :single_script_confusable},
          {"scope", "ѕсоре", :whole_script_confusable},
          {"paypal", "pаypаl", :mixed_script_confusable},
          {"é", "e\u0301", :none},
          {"alice", "bob", :none}
        ],
        type <- [:username, :tenant_slug, :organization_name] do
      comparison = UnicodeSecurity.compare(left, right, type: type)
      assert comparison.class == class
      assert comparison.left_skeleton == UnicodeSecurity.skeleton(left)
      assert comparison.right_skeleton == UnicodeSecurity.skeleton(right)

      assert Enum.count(comparison.mappings, &(&1.side == :left)) ==
               length(String.to_charlist(left))

      assert Enum.count(comparison.mappings, &(&1.side == :right)) ==
               length(String.to_charlist(right))
    end

    assert UnicodeSecurity.compare("", "m").left_resolved_scripts == :all
    assert UnicodeSecurity.compare("!", "m").left_resolved_scripts == :all

    assert UnicodeSecurity.compare("漢", "字").left_resolved_scripts ==
             [:han, :hanb, :hntl, :jpan, :kore]
  end

  test "comparison validates options before malformed content and inputs left to right" do
    for options <- [nil, [type: :domain], [policy: :default], [type: :username, type: :username]] do
      assert_raise ArgumentError, fn -> UnicodeSecurity.compare(<<255>>, <<255>>, options) end
    end

    for type <- [:username, :tenant_slug, :organization_name] do
      assert %UnicodeSecurity.Comparison{} = UnicodeSecurity.compare("m", "rn", type: type)
    end

    for {left, right, offset, reason} <- [
          {"a" <> <<255>>, <<255>>, 1, :invalid_utf8},
          {"ok", "a" <> <<255>>, 1, :invalid_utf8},
          {String.duplicate("a", 4097), <<255>>, 4096, :input_too_long}
        ] do
      error = assert_raise InvalidInputError, fn -> UnicodeSecurity.compare(left, right) end
      assert {error.byte_offset, error.reason} == {offset, reason}
    end
  end

  test "swapped comparison exchanges facts and evidence sides" do
    forward = UnicodeSecurity.compare("m", "rn")
    reverse = UnicodeSecurity.compare("rn", "m")

    assert forward.same_skeleton? == reverse.same_skeleton?
    assert forward.confusable? == reverse.confusable?
    assert forward.class == reverse.class
    assert forward.left_skeleton == reverse.right_skeleton
    assert forward.right_skeleton == reverse.left_skeleton

    for side <- [:left, :right] do
      opposite = if side == :left, do: :right, else: :left

      assert Enum.filter(forward.mappings, &(&1.side == side))
             |> Enum.map(&Map.delete(&1, :side)) ==
               Enum.filter(reverse.mappings, &(&1.side == opposite))
               |> Enum.map(&Map.delete(&1, :side))
    end
  end

  test "identical invalid inputs never bypass validation" do
    for input <- [<<255>>, String.duplicate("a", 4097)] do
      for operation <- [&UnicodeSecurity.same_skeleton?/2, &UnicodeSecurity.confusable?/2] do
        assert_raise InvalidInputError, fn -> operation.(input, input) end
      end
    end
  end

  test "pair facts distinguish the three classes and retain complete facts" do
    for {left, right, class} <- [
          {"m", "rn", :single_script_confusable},
          {"scope", "ѕсоре", :whole_script_confusable},
          {"paypal", "pаypаl", :mixed_script_confusable},
          {"é", "e\u0301", :none},
          {"alice", "bob", :none}
        ] do
      a = Pair.prepare(left)
      b = Pair.prepare(right)
      comparison = Pair.compare_prepared(a, b)
      assert comparison.class == class
      assert comparison.same_skeleton? == (a.skeleton == b.skeleton)
      assert comparison.canonically_equivalent? == (a.nfd == b.nfd)
      assert comparison.confusable? == (class != :none)
      assert comparison.left_skeleton == a.skeleton
      assert comparison.right_skeleton == b.skeleton
      assert comparison.left_scripts == a.scripts
      assert comparison.right_scripts == b.scripts
      assert comparison.left_resolved_scripts == a.resolved
      assert comparison.right_resolved_scripts == b.resolved
      assert comparison.unicode_version == "18.0.0"
      assert comparison.mappings == []
    end
  end

  test "resolved-set classification handles neutral, empty and synthetic intersections" do
    for {left, right, expected} <- [
          {:all, :all, :single_script_confusable},
          {:all, [:latin], :single_script_confusable},
          {[:latin], :all, :single_script_confusable},
          {:all, [], :mixed_script_confusable},
          {[], :all, :mixed_script_confusable},
          {[], [], :mixed_script_confusable},
          {[], [:latin], :mixed_script_confusable},
          {[:latin], [], :mixed_script_confusable},
          {[:latin], [:cyrillic], :whole_script_confusable},
          {[:hntl, :latin], [:han, :hntl], :single_script_confusable}
        ] do
      assert Pair.classify_sets(left, right) == expected
    end
  end

  test "input validation visits left then right, including 4096-byte boundary" do
    valid = String.duplicate("a", 4096)
    malformed = "a" <> <<255>>
    oversized = valid <> "a"

    for {operation, expected} <- [
          {&UnicodeSecurity.same_skeleton?/2, true},
          {&UnicodeSecurity.confusable?/2, false}
        ] do
      assert operation.(valid, valid) == expected

      for {left, right} <- [{nil, valid}, {valid, nil}] do
        assert_raise ArgumentError, fn -> operation.(left, right) end
      end

      for {left, right, offset, reason} <- [
            {malformed, valid, 1, :invalid_utf8},
            {valid, malformed, 1, :invalid_utf8},
            {oversized, valid, 4096, :input_too_long},
            {valid, oversized, 4096, :input_too_long},
            {malformed, <<255>>, 1, :invalid_utf8}
          ] do
        error = assert_raise InvalidInputError, fn -> operation.(left, right) end
        assert {error.byte_offset, error.reason} == {offset, reason}
      end
    end
  end

  test "canonical variants include Hangul decomposition and reordered unequal classes" do
    for {left, right} <- [{"가", "가"}, {"a\u0315\u0300", "a\u0300\u0315"}] do
      assert UnicodeSecurity.same_skeleton?(left, right)
      refute UnicodeSecurity.confusable?(left, right)
      assert Pair.compare_prepared(Pair.prepare(left), Pair.prepare(right)).class == :none
    end
  end

  test "optional type options reject invalid values without normalization" do
    assert ComparisonOptions.resolve!([], :optional) == nil

    for type <- [:username, :tenant_slug, :organization_name] do
      assert ComparisonOptions.resolve!([type: type], :optional) == type
      assert ComparisonOptions.resolve!([type: type], :required) == type
    end

    for options <- [
          nil,
          [type: nil],
          [type: :domain],
          [type: :username, type: :username],
          [policy: :default],
          [allowed_scripts: [:latin]],
          [denied_scripts: [:latin]],
          [{:type, :username} | :bad],
          %{},
          [unknown: true]
        ] do
      for mode <- [:optional, :required] do
        assert_raise ArgumentError, fn -> ComparisonOptions.resolve!(options, mode) end
      end
    end

    assert_raise ArgumentError, fn -> ComparisonOptions.resolve!([], :required) end
  end

  property "pair predicates are symmetric and prepared resolved sets match pinned scripts" do
    scalar = integer(0..0x10FFFF) |> filter(&(&1 not in 0xD800..0xDFFF))

    check all(
            left_codes <- list_of(scalar, max_length: 40),
            right_codes <- list_of(scalar, max_length: 40),
            max_runs: 40
          ) do
      left = for code <- left_codes, into: "", do: <<code::utf8>>
      right = for code <- right_codes, into: "", do: <<code::utf8>>
      equal? = UnicodeSecurity.same_skeleton?(left, right)
      confusable? = UnicodeSecurity.confusable?(left, right)
      assert equal? == UnicodeSecurity.same_skeleton?(right, left)
      assert confusable? == UnicodeSecurity.confusable?(right, left)
      assert not confusable? or equal?

      for {input, codes} <- [{left, left_codes}, {right, right_codes}] do
        resolved = Scripts.resolved_set(codes)

        expected =
          if resolved == :all, do: :all, else: resolved |> MapSet.to_list() |> Enum.sort()

        assert Pair.prepare(input).resolved == expected
      end
    end
  end
end
