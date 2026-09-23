defmodule UnicodeSecurity.SkeletonTraceTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.{Bidi, Normalization, SkeletonTrace, Utf8}
  alias UnicodeSecurity.Test.UnicodeFixtures

  test "trace keeps a decomposed source across separated target spans" do
    decoded = Utf8.decode!("á\u0327")

    assert {"a\u0326\u0301", [first, second]} = SkeletonTrace.trace(decoded, :left)

    assert first == %{
             side: :left,
             byte_offset: 0,
             byte_length: 2,
             codepoint_index: 0,
             codepoint_count: 1,
             codepoints: [0xE1],
             mapping: "a\u0301",
             skeleton_spans: [
               %{codepoint_index: 0, codepoint_count: 1},
               %{codepoint_index: 2, codepoint_count: 1}
             ]
           }

    assert second == %{
             side: :left,
             byte_offset: 2,
             byte_length: 2,
             codepoint_index: 1,
             codepoint_count: 1,
             codepoints: [0x327],
             mapping: "\u0326",
             skeleton_spans: [%{codepoint_index: 1, codepoint_count: 1}]
           }
  end

  test "paragraph offsets and removed characters remain original" do
    decoded = Utf8.decode!("m\n\u200D\u0000𝐀")
    {key, mappings} = SkeletonTrace.trace(decoded, :right)

    assert key == "rn\nA"
    assert Enum.map(mappings, & &1.byte_offset) == [0, 1, 2, 5, 6]
    assert Enum.map(mappings, & &1.codepoint_index) == [0, 1, 2, 3, 4]
    assert Enum.map(mappings, & &1.mapping) == ["rn", "\n", "", "", "A"]
    assert List.last(mappings).byte_length == 4
  end

  test "normative bidi mirror and mark provenance follows original coordinates" do
    for {input, side, offsets, targets, values} <- [
          {"A1<ש\u05C2", :left, [0, 1, 2, 3, 5], [0, 1, 2, 3, 4], ["A", "l", "<", "ש", "\u0307"]},
          {"Αש\u05BA>1", :right, [0, 2, 4, 6, 7], [0, 3, 4, 2, 1], ["A", "ש", "\u0307", "<", "l"]}
        ] do
      {key, mappings} = SkeletonTrace.trace(Utf8.decode!(input), side)
      assert key == "Al<ש\u0307"
      assert Enum.map(mappings, & &1.byte_offset) == offsets
      assert Enum.map(mappings, & &1.mapping) == values

      assert Enum.map(mappings, fn mapping ->
               assert mapping.side == side
               assert mapping.codepoint_count == 1
               assert [%{codepoint_index: index, codepoint_count: 1}] = mapping.skeleton_spans
               index
             end) == targets
    end
  end

  test "tagged transforms preserve scalar projections and stable mark origins" do
    for scalars <- [
          [],
          ~c"ASCII",
          [0x301, 0x323, ?q, 0x307, 0x301, 0x323],
          [0xAC01, 0x1D15E, 0x327],
          [0x202E, ?a, 0x300, 0x301, 0x2140, 0x202C],
          ~c"Αשֺ>1"
        ] do
      assert Bidi.reorder_with_indexes(scalars) |> Enum.map(&elem(&1, 0)) ==
               Bidi.reorder(scalars)

      tagged = Enum.with_index(scalars)

      assert Normalization.nfd_tagged(tagged) |> Enum.map(&elem(&1, 0)) ==
               Normalization.nfd_scalars(scalars)
    end

    assert Normalization.nfd_tagged([{?q, 0}, {0x307, 1}, {0x301, 2}, {0x323, 3}]) ==
             [{?q, 0}, {0x323, 3}, {0x307, 1}, {0x301, 2}]

    assert Normalization.nfd_tagged([{0xAC01, 7}]) ==
             [{0x1100, 7}, {0x1161, 7}, {0x11A8, 7}]
  end

  test "tagged NFD agrees with every official NFD row" do
    count =
      Enum.reduce(UnicodeFixtures.normalization_rows(), 0, fn {_line, columns}, count ->
        for input <- columns do
          scalars = String.to_charlist(input)

          assert Normalization.nfd_tagged(Enum.with_index(scalars))
                 |> Enum.map(&elem(&1, 0)) == Normalization.nfd_scalars(scalars)
        end

        count + 1
      end)

    assert count == 20_171
  end

  test "empty, all removed, leading marks, and large expansion retain complete evidence" do
    for {input, expected} <- [
          {"", ""},
          {"\u200D\u0000", ""},
          {"\u0307\u0323q", "\u0323\u0307q"},
          {String.duplicate("m", 4096), String.duplicate("rn", 4096)}
        ] do
      {key, mappings} = SkeletonTrace.trace(Utf8.decode!(input), :left)
      assert key == expected
      assert length(mappings) == length(String.to_charlist(input))
      assert_trace(input, key, mappings)
    end
  end

  property "trace records partition the target and reproduce each source contribution" do
    scalar = integer(0..0x10FFFF) |> filter(&(&1 not in 0xD800..0xDFFF))

    check all(codes <- list_of(scalar, max_length: 40), max_runs: 40) do
      input = for code <- codes, into: "", do: <<code::utf8>>
      {key, mappings} = SkeletonTrace.trace(Utf8.decode!(input), :left)
      assert key == UnicodeSecurity.skeleton(input)
      assert_trace(input, key, mappings)
    end
  end

  defp assert_trace(input, key, mappings) do
    target = String.to_charlist(key)
    source = Utf8.decode!(input)
    assert length(mappings) == length(source)

    contributions =
      source
      |> Enum.with_index()
      |> Enum.flat_map(fn {{scalar, offset}, index} ->
        mapping = Enum.at(mappings, index)
        assert mapping.codepoint_index == index
        assert mapping.codepoint_count == 1
        assert mapping.codepoints == [scalar]
        assert mapping.byte_offset == offset
        assert mapping.byte_length == byte_size(<<scalar::utf8>>)
        assert binary_part(input, offset, mapping.byte_length) == <<scalar::utf8>>

        positions =
          Enum.flat_map(mapping.skeleton_spans, fn %{
                                                     codepoint_index: start,
                                                     codepoint_count: count
                                                   } ->
            Enum.to_list(start..(start + count - 1))
          end)

        assert positions == Enum.sort(positions)
        assert Enum.map(positions, &Enum.at(target, &1)) == String.to_charlist(mapping.mapping)
        Enum.map(positions, &{&1, Enum.at(target, &1)})
      end)

    assert Enum.sort(contributions) ==
             Enum.with_index(target) |> Enum.map(fn {scalar, index} -> {index, scalar} end)

    assert contributions
           |> Enum.sort()
           |> Enum.map(fn {_index, scalar} -> <<scalar::utf8>> end)
           |> IO.iodata_to_binary() == key
  end
end
