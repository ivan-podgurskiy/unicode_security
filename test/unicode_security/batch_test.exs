defmodule UnicodeSecurity.BatchTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.Batch.Classes
  alias UnicodeSecurity.{BatchResult, Collision, Duplicate, Normalization, Scripts}

  test "duplicates and distinct key collisions retain every occurrence" do
    inputs = ["m", "m", "rn"]
    batch = UnicodeSecurity.check_many(inputs, type: :username)
    assert %BatchResult{} = batch
    assert batch.results == Enum.to_list(UnicodeSecurity.audit(inputs, type: :username))
    assert [%Duplicate{input: "m", indexes: [0, 1], reasons: [duplicate]}] = batch.duplicates
    assert duplicate.code == :exact_duplicate and duplicate.severity == :info

    assert [
             %Collision{
               key: "rn",
               inputs: ^inputs,
               indexes: [0, 1, 2],
               class: :single_script_confusable,
               classes: [:single_script_confusable],
               reasons: reasons
             }
           ] = batch.collisions

    assert Enum.map(reasons, & &1.code) ==
             [:single_script_confusable, :skeleton_collision]

    assert Enum.all?(reasons, &(&1.severity == :high and &1.details == %{indexes: [0, 1, 2]}))
    assert Enum.all?(batch.results, &(&1.result.verdict == :safe and &1.result.reasons == []))
  end

  test "canonical-only collisions and malformed duplicates retain their distinctions" do
    batch = UnicodeSecurity.check_many(["é", "e\u0301", <<255>>, <<255>>, nil], type: :username)

    assert [
             %{
               indexes: [0, 1],
               class: :none,
               classes: [],
               reasons: [%{code: :skeleton_collision}]
             }
           ] =
             batch.collisions

    assert [%{input: <<255>>, indexes: [2, 3]}] = batch.duplicates
    assert Enum.map(batch.results, & &1.result.valid_input?) == [true, true, false, false, false]

    assert Enum.at(batch.results, 4).result.reasons |> hd() |> Map.fetch!(:code) ==
             :invalid_item_type
  end

  test "empty, only repeated, and first encounter ordering" do
    empty = UnicodeSecurity.check_many([], type: :username)

    assert {empty.results, empty.duplicates, empty.collisions, empty.unicode_version} ==
             {[], [], [], "18.0.0"}

    repeated = UnicodeSecurity.check_many(["m", "m"], type: :username)
    assert [%{indexes: [0, 1]}] = repeated.duplicates
    assert repeated.collisions == []

    inputs = ["m", "x", "rn", "x", "m", "é", "e\u0301", <<255>>, <<255>>]
    batch = UnicodeSecurity.check_many(inputs, type: :username)
    assert Enum.map(batch.results, & &1.input) == inputs
    assert Enum.map(batch.duplicates, & &1.indexes) == [[0, 4], [1, 3], [7, 8]]
    assert Enum.map(batch.collisions, & &1.indexes) == [[0, 2, 4], [5, 6]]
    assert Enum.map(batch.collisions, & &1.class) == [:single_script_confusable, :none]
  end

  test "repeated oversized binaries, nonbinary terms and empty computed keys" do
    oversized = String.duplicate("a", 4097)
    inputs = [oversized, nil, oversized, nil, "", "\u200D"]
    batch = UnicodeSecurity.check_many(inputs, type: :username)
    assert [%{input: ^oversized, indexes: [0, 2]}] = batch.duplicates
    assert [%{key: "", indexes: [4, 5], inputs: ["", "\u200D"]}] = batch.collisions

    assert Enum.map(batch.results, & &1.result.valid_input?) ==
             [false, false, false, false, true, true]

    assert batch.results == Enum.to_list(UnicodeSecurity.audit(inputs, type: :username))
  end

  test "collection severities follow all presets without changing item results" do
    for type <- [:username, :tenant_slug, :organization_name],
        {preset, severity} <- [strict: :critical, default: :high, permissive: :medium] do
      options = [type: type, policy: preset]
      batch = UnicodeSecurity.check_many(["m", "m", "rn", "é", "e\u0301"], options)

      assert batch.results ==
               Enum.to_list(UnicodeSecurity.audit(["m", "m", "rn", "é", "e\u0301"], options))

      assert Enum.map(hd(batch.collisions).reasons, &{&1.code, &1.severity}) ==
               [{:single_script_confusable, severity}, {:skeleton_collision, severity}]

      assert Enum.map(List.last(batch.collisions).reasons, &{&1.code, &1.severity}) ==
               [{:skeleton_collision, severity}]

      assert [%{reasons: [%{code: :exact_duplicate, severity: :info}]}] = batch.duplicates

      assert Enum.all?(batch.collisions, fn collision ->
               Enum.all?(collision.reasons, fn reason ->
                 reason.byte_offset == nil and reason.codepoint_index == nil and
                   reason.details == %{indexes: collision.indexes}
               end)
             end)
    end
  end

  test "heterogeneous bucket retains all three classes in precedence order" do
    inputs = ["scope", "ѕсоре", "scоpe", "𝐬𝐜𝐨𝐩𝐞"]

    assert Enum.map(inputs, &UnicodeSecurity.conflict_key(&1, type: :organization_name)) ==
             ["scope", "scope", "scope", "scope"]

    assert [
             %{
               class: :mixed_script_confusable,
               classes: [
                 :mixed_script_confusable,
                 :whole_script_confusable,
                 :single_script_confusable
               ],
               indexes: [0, 1, 2, 3]
             }
           ] =
             UnicodeSecurity.check_many(inputs, type: :organization_name).collisions
  end

  test "signature summaries keep two canonical representatives and test self-pairs" do
    assert Classes.finish(%{[:latin] => [[?a]]}) == []
    assert Classes.finish(%{[:latin] => [[?a], [?b]]}) == [:single_script_confusable]
    assert Classes.finish(%{[:latin] => [[?a]], [:greek] => [[?a]]}) == []
    assert Classes.finish(%{[:latin] => [[?a]], [:greek] => [[?b]]}) == [:whole_script_confusable]
    assert Classes.finish(%{[] => [[?a], [?b]]}) == [:mixed_script_confusable]

    signatures = Enum.reduce([[?a], [?a], [?b], [?c]], %{}, &Classes.add(&2, [:latin], &1))
    assert length(signatures[[:latin]]) == 2
    assert Classes.finish(signatures) == [:single_script_confusable]
  end

  test "compressed signature summaries agree with uncompressed canonical pairs" do
    summaries = [
      %{[:latin] => [[?a], [?a], [?b], [?c]]},
      %{[:latin] => [[?a], [?b], [?c]], :all => [[?a]]},
      %{[:latin] => [[?a]], [:greek] => [[?a], [?b], [?c]]},
      %{[] => [[?a], [?b], [?c]], :all => [[?a]]},
      %{[:hntl, :latin] => [[?a]], [:han, :hntl] => [[?b]]},
      %{[:latin] => [[?a], [?b]], [:greek] => [[?b]], [] => [[?c]], :all => [[?d]]}
    ]

    for full <- summaries do
      compressed =
        Enum.reduce(full, %{}, fn {signature, canonicals}, acc ->
          Enum.reduce(canonicals, acc, &Classes.add(&2, signature, &1))
        end)

      assert Enum.all?(compressed, fn {_signature, canonicals} -> length(canonicals) <= 2 end)
      assert Classes.finish(compressed) == oracle_summary_classes(full)
    end
  end

  test "valid configuration is checked before source and map items follow enumeration" do
    source = Stream.map(["m"], fn _ -> flunk("source was pulled") end)
    assert_raise ArgumentError, fn -> UnicodeSecurity.check_many(source, []) end

    assert_raise ArgumentError, "expected an enumerable", fn ->
      UnicodeSecurity.check_many(42, type: :username)
    end

    assert_raise ArgumentError, "unsupported or missing type", fn ->
      UnicodeSecurity.check_many(42, [])
    end

    map = %{a: "m", b: "rn"}

    assert UnicodeSecurity.check_many(map, type: :username).results ==
             Enum.to_list(UnicodeSecurity.audit(map, type: :username))
  end

  test "duplicate-heavy input retains every occurrence" do
    inputs = List.duplicate("m", 5_000) ++ ["rn"]
    batch = UnicodeSecurity.check_many(inputs, type: :username)
    assert length(batch.results) == 5_001
    assert [%{indexes: indexes}] = batch.duplicates
    assert indexes == Enum.to_list(0..4_999)

    assert [%{indexes: collision_indexes, inputs: ^inputs, classes: [:single_script_confusable]}] =
             batch.collisions

    assert collision_indexes == Enum.to_list(0..5_000)
  end

  test "check_many consumes a resource once and runs its cleanup" do
    parent = self()

    source =
      Stream.resource(
        fn -> 0 end,
        fn
          2 ->
            {:halt, 2}

          n ->
            send(parent, {:pulled, n})
            {[Enum.at(["m", "rn"], n)], n + 1}
        end,
        fn _ -> send(parent, :closed) end
      )

    assert [%{indexes: [0, 1]}] = UnicodeSecurity.check_many(source, type: :username).collisions
    assert_received {:pulled, 0}
    assert_received {:pulled, 1}
    assert_received :closed
    refute_received {:pulled, _}
    refute_received :closed
  end

  property "small real buckets agree with an independent all-pairs classifier" do
    values = ["m", "rn", "scope", "ѕсоре", "scоpe", "𝐬𝐜𝐨𝐩𝐞", "é", "é", "", "\u200D"]

    check all(indices <- list_of(integer(0..9), max_length: 8), max_runs: 40) do
      inputs = Enum.map(indices, &Enum.at(values, &1))
      batch = UnicodeSecurity.check_many(inputs, type: :organization_name)

      for collision <- batch.collisions do
        assert collision.classes == oracle_classes(collision.inputs)
      end
    end
  end

  property "batch items equal audit under arbitrary values and selected policies" do
    check all(
            inputs <-
              list_of(one_of([binary(max_length: 12), member_of([nil, 1, :bad])]), max_length: 12),
            type <- member_of([:username, :tenant_slug, :organization_name]),
            preset <- member_of([:strict, :default, :permissive]),
            max_runs: 30
          ) do
      options = [type: type, policy: preset]

      assert UnicodeSecurity.check_many(inputs, options).results ==
               Enum.to_list(UnicodeSecurity.audit(inputs, options))
    end
  end

  defp oracle_classes(inputs) do
    facts =
      inputs
      |> Enum.uniq()
      |> Enum.map(fn input ->
        scalars = String.to_charlist(input)
        {Normalization.nfd_scalars(scalars), Scripts.resolved_set(scalars)}
      end)

    for {left, i} <- Enum.with_index(facts),
        {right, j} <- Enum.with_index(facts),
        i < j,
        elem(left, 0) != elem(right, 0),
        reduce: MapSet.new() do
      classes -> MapSet.put(classes, oracle_class(elem(left, 1), elem(right, 1)))
    end
    |> then(fn classes ->
      Enum.filter(
        [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable],
        &MapSet.member?(classes, &1)
      )
    end)
  end

  defp oracle_class(left, right) do
    cond do
      left == MapSet.new() or right == MapSet.new() -> :mixed_script_confusable
      left == :all or right == :all -> :single_script_confusable
      MapSet.disjoint?(left, right) -> :whole_script_confusable
      true -> :single_script_confusable
    end
  end

  defp oracle_summary_classes(summary) do
    facts =
      for {signature, canonicals} <- summary,
          canonical <- canonicals,
          do: {canonical, signature_to_set(signature)}

    for {left, i} <- Enum.with_index(facts),
        {right, j} <- Enum.with_index(facts),
        i < j,
        elem(left, 0) != elem(right, 0),
        reduce: MapSet.new() do
      classes -> MapSet.put(classes, oracle_class(elem(left, 1), elem(right, 1)))
    end
    |> then(fn classes ->
      Enum.filter(
        [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable],
        &MapSet.member?(classes, &1)
      )
    end)
  end

  defp signature_to_set(:all), do: :all
  defp signature_to_set(signature), do: MapSet.new(signature)
end
