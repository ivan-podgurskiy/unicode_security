defmodule UnicodeSecurity.DomainComparisonTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.{Domain, InvalidDomainError, InvalidInputError}

  test "IDNA equality is distinct from raw canonical equivalence" do
    comparison = UnicodeSecurity.compare("bücher.a", "XN--BCHER-KVA.a.", type: :domain)
    assert comparison.same_skeleton?
    refute comparison.confusable?
    refute comparison.canonically_equivalent?
    assert comparison.class == :none
    assert comparison.left_skeleton == "bücher.a"
    assert comparison.right_skeleton == comparison.left_skeleton
  end

  test "changed labels alone determine the primary class" do
    whole = UnicodeSecurity.compare("а.a", "a.a", type: :domain)
    assert whole.confusable?
    assert whole.class == :whole_script_confusable

    mixed = UnicodeSecurity.compare("pаypal.a", "paypal.a", type: :domain)
    assert mixed.class == :mixed_script_confusable

    single = UnicodeSecurity.compare("m.a", "rn.a", type: :domain)
    assert single.class == :single_script_confusable

    unequal = UnicodeSecurity.compare("а.a", "a.b", type: :domain)
    refute unequal.confusable?
    assert unequal.class == :none
  end

  test "root separator and ignored root source have empty contributions" do
    comparison = UnicodeSecurity.compare("a.\u00AD", "A", type: :domain)
    left = Enum.filter(comparison.mappings, &(&1.side == :left))
    assert Enum.map(left, & &1.codepoints) == [[?a], [?.], [0xAD]]
    assert Enum.map(left, & &1.mapping) == ["a", "", ""]

    assert Enum.map(left, & &1.skeleton_spans) ==
             [[%{codepoint_index: 0, codepoint_count: 1}], [], []]
  end

  test "whole-label evidence partitions original and target scalar coordinates" do
    for {left, right} <- [
          {"BÜCHER。a.\u00AD", "xn--bcher-kva.a"},
          {"ＦＯＯ.a", "foo.a"},
          {"a.", "a"},
          {"e\u0306.а", "ĕ.a"},
          {"a۰b.c", "a۰b.c"},
          {"a.b۰c", "a.b۰c"},
          {"𞤀.a", "𞤀.a"},
          {"مثال.إختبار", "مثال.إختبار"}
        ] do
      comparison = UnicodeSecurity.compare(left, right, type: :domain)
      assert_partition(left, comparison.left_skeleton, comparison.mappings, :left)
      assert_partition(right, comparison.right_skeleton, comparison.mappings, :right)
    end
  end

  test "each separator variant is a whole source unit with one target dot" do
    for separator <- [".", "。", "．", "｡"] do
      comparison = UnicodeSecurity.compare("a" <> separator <> "b", "a.b", type: :domain)
      left = Enum.filter(comparison.mappings, &(&1.side == :left))
      assert Enum.map(left, & &1.mapping) == ["a", ".", "b"]
      assert Enum.at(left, 1).byte_length == byte_size(separator)
      assert_partition("a" <> separator <> "b", "a.b", comparison.mappings, :left)
    end
  end

  test "escaped dot and percent consume their full target spans" do
    validated = Domain.validate!("a")
    facts = Domain.prepare(validated, "a")

    for {payload, escaped} <- [{".", "%2E"}, {"%", "%25"}] do
      synthetic = %{facts | skeleton: escaped, labels: [%{hd(facts.labels) | skeleton: payload}]}
      assert {^escaped, [record]} = Domain.Comparison.trace(synthetic, :left)
      assert record.mapping == escaped
      assert record.skeleton_spans == [%{codepoint_index: 0, codepoint_count: 3}]
    end

    comparison = UnicodeSecurity.compare("a۰b.c", "a۰b.c", type: :domain)
    assert_partition("a۰b.c", "a%2Eb.c", comparison.mappings, :left)
  end

  test "domain configuration and validity fail in defined order" do
    assert_raise ArgumentError, fn ->
      UnicodeSecurity.compare(<<255>>, "xn--abc-", type: :domain, policy: :default)
    end

    first =
      assert_raise InvalidDomainError, fn ->
        UnicodeSecurity.compare("xn--abc-", "a..b", type: :domain)
      end

    assert {first.reason, first.byte_offset} == {:domain_invalid_alabel, 0}

    second =
      assert_raise InvalidDomainError, fn ->
        UnicodeSecurity.compare("a", "xn--abc-", type: :domain)
      end

    assert second.reason == :domain_invalid_alabel
    assert Exception.message(second) == "Input is not a valid domain name"

    for input <- [<<255>>, String.duplicate("a", 4097)] do
      assert_raise InvalidInputError, fn -> UnicodeSecurity.compare(input, "a", type: :domain) end
    end
  end

  test "generic comparison retains original meaning for dotted inputs" do
    assert UnicodeSecurity.compare("a.", "a").same_skeleton? == false
    assert UnicodeSecurity.compare("a.", "a", type: :domain).same_skeleton?
    assert Domain.key(Domain.validate!("a.")) == "a"
  end

  defp assert_partition(input, key, all_mappings, side) do
    mappings = Enum.filter(all_mappings, &(&1.side == side))
    original = String.to_charlist(input)
    target = String.to_charlist(key)

    {byte_end, scalar_end, target_end} =
      Enum.reduce(mappings, {0, 0, 0}, fn mapping, {byte_at, scalar_at, target_at} ->
        assert map_size(mapping) == 8
        assert mapping.byte_offset == byte_at
        assert mapping.codepoint_index == scalar_at

        assert mapping.codepoints ==
                 Enum.slice(original, scalar_at, mapping.codepoint_count)

        assert binary_part(input, byte_at, mapping.byte_length) ==
                 mapping.codepoints |> Enum.map(&<<&1::utf8>>) |> IO.iodata_to_binary()

        count = length(String.to_charlist(mapping.mapping))

        assert mapping.skeleton_spans ==
                 if(count == 0,
                   do: [],
                   else: [%{codepoint_index: target_at, codepoint_count: count}]
                 )

        assert String.to_charlist(mapping.mapping) == Enum.slice(target, target_at, count)

        {byte_at + mapping.byte_length, scalar_at + mapping.codepoint_count, target_at + count}
      end)

    assert {byte_end, scalar_end, target_end} ==
             {byte_size(input), length(original), length(target)}
  end
end
