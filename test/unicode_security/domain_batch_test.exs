defmodule UnicodeSecurity.DomainBatchTest do
  use ExUnit.Case, async: false

  alias UnicodeSecurity.{
    Batch,
    Collision,
    Domain,
    Duplicate,
    Idna,
    Pair,
    Reason,
    SkeletonTrace,
    Utf8
  }

  alias UnicodeSecurity.Batch.Groups

  @precedence [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable]

  test "equivalent IDNA forms collide while invalid originals still duplicate" do
    inputs = ["A", "a.", "A", "a..", "a..", nil]
    batch = UnicodeSecurity.check_many(inputs, type: :domain)

    assert batch.results == Enum.to_list(UnicodeSecurity.audit(inputs, type: :domain))

    assert Enum.map(batch.duplicates, &{&1.input, &1.indexes}) ==
             [{"A", [0, 2]}, {"a..", [3, 4]}]

    assert [collision] = batch.collisions
    assert collision.indexes == [0, 1, 2]
    assert collision.inputs == ["A", "a.", "A"]
    assert collision.class == :none and collision.classes == []
    assert Enum.map(collision.reasons, & &1.code) == [:skeleton_collision]
  end

  test "a weaker label class paired with a stronger one is not observed primary" do
    batch = UnicodeSecurity.check_many(["aа.а", "aa.a"], type: :domain)
    assert [collision] = batch.collisions
    assert collision.classes == [:mixed_script_confusable]
    assert collision.class == :mixed_script_confusable
  end

  test "U-label and A-label spellings share a class-none bucket" do
    inputs = ["bücher.a", "xn--bcher-kva.a"]
    batch = UnicodeSecurity.check_many(inputs, type: :domain)

    assert [collision] = batch.collisions
    assert collision.inputs == inputs
    assert collision.indexes == [0, 1]
    assert collision.class == :none
    assert collision.classes == []
    assert Enum.map(collision.reasons, & &1.code) == [:skeleton_collision]
    assert Enum.map(batch.results, & &1.result.domain.unicode) == ["bücher.a", "bücher.a"]
  end

  test "domain buckets preserve occurrence and first-key order" do
    inputs = ["a.a", "A.a", "x.x", "а.a", "a.a", "X.x", "a..", "a..", nil]
    batch = UnicodeSecurity.check_many(inputs, type: :domain)

    assert Enum.map(batch.results, & &1.input) == inputs

    assert Enum.map(batch.duplicates, &{&1.input, &1.indexes}) ==
             [{"a.a", [0, 4]}, {"a..", [6, 7]}]

    assert Enum.map(batch.collisions, & &1.indexes) == [[0, 1, 3, 4], [2, 5]]

    assert Enum.map(batch.collisions, & &1.inputs) ==
             [["a.a", "A.a", "а.a", "a.a"], ["x.x", "X.x"]]
  end

  test "all presets set collection severities and retain item results" do
    for {preset, severity} <- [strict: :critical, default: :high, permissive: :medium] do
      options = [type: :domain, policy: preset]
      inputs = ["aа.а", "aa.a", "aа.а"]
      batch = UnicodeSecurity.check_many(inputs, options)

      assert batch.results == Enum.to_list(UnicodeSecurity.audit(inputs, options))
      assert [collision] = batch.collisions
      assert collision.indexes == [0, 1, 2]
      assert collision.classes == [:mixed_script_confusable]

      assert Enum.map(collision.reasons, &{&1.code, &1.severity}) ==
               [{:mixed_script_confusable, severity}, {:skeleton_collision, severity}]

      assert [%{input: "aа.а", indexes: [0, 2], reasons: [%{severity: :info}]}] =
               batch.duplicates
    end
  end

  test "no-hit domains and one spelling produce no collision" do
    assert UnicodeSecurity.check_many(["a.a", "b.b", "a..", nil], type: :domain).collisions == []
    assert UnicodeSecurity.check_many(["a.a", "a.a"], type: :domain).collisions == []
  end

  test "audit stays lazy for an infinite domain source and producer failures propagate" do
    parent = self()

    source =
      Stream.iterate(0, &(&1 + 1))
      |> Stream.map(fn index ->
        send(parent, {:domain_pulled, index})
        "a.a"
      end)

    stream = UnicodeSecurity.audit(source, type: :domain)
    refute_received {:domain_pulled, _}
    assert Enum.map(Enum.take(stream, 2), & &1.index) == [0, 1]
    assert_received {:domain_pulled, 0}
    assert_received {:domain_pulled, 1}
    refute_received {:domain_pulled, _}

    assert_raise ArgumentError, fn ->
      UnicodeSecurity.audit(source, type: :domain, policy: :bad)
    end

    refute_received {:domain_pulled, _}

    failing = Stream.map(["a.a"], fn _ -> raise "domain producer error" end)

    assert_raise RuntimeError, "domain producer error", fn ->
      UnicodeSecurity.check_many(failing, type: :domain)
    end
  end

  test "domain audit validates the Enumerable protocol immediately" do
    assert_raise ArgumentError, "expected an enumerable", fn ->
      UnicodeSecurity.audit(123, type: :domain)
    end
  end

  test "complete batch output matches a direct all-pairs oracle across small permutations" do
    names = [
      "a.a",
      "а.a",
      "a.а",
      "а.а",
      "aa.a",
      "aа.а",
      "aa.а",
      "Ａ.A.",
      "A.a",
      "bücher.a",
      "xn--bcher-kva.a",
      "BÜCHER.a",
      "a..",
      nil
    ]

    for size <- 0..3,
        subset <- combinations(names, size),
        inputs <- permutations(subset) do
      batch = UnicodeSecurity.check_many(inputs, type: :domain)
      assert batch.results == Enum.to_list(UnicodeSecurity.audit(inputs, type: :domain))

      assert batch.collisions == oracle_groups(batch.results)
      assert batch.duplicates == oracle_duplicates(inputs)
    end
  end

  test "grouping completed domain items does not repeat decoding, IDNA, or traces" do
    policy = UnicodeSecurity.Policy.resolve!(type: :domain)

    items =
      for {input, index} <- Enum.with_index(["aа.а", "aa.a"]),
          do: Batch.item(input, index, policy)

    watched = [
      {Utf8, :decode!, 1},
      {Idna, :to_ascii, 1},
      {Domain, :validate!, 1},
      {Domain, :prepare, 2},
      {Pair, :prepare, 1},
      {Pair, :from_decoded, 2},
      {SkeletonTrace, :trace, 2},
      {Domain.Comparison, :trace, 2}
    ]

    for spec <- watched, do: :erlang.trace_pattern(spec, true, [:local])
    :erlang.trace(self(), true, [:call])

    try do
      result = Enum.reduce(items, Groups.new(), &Groups.add(&2, &1)) |> Groups.finish(policy)
      assert [%{classes: [:mixed_script_confusable]}] = result.collisions
    after
      :erlang.trace(self(), false, [:call])
      for spec <- watched, do: :erlang.trace_pattern(spec, false, [:local])
    end

    assert trace_calls() == []
  end

  defp oracle_groups(results) do
    results
    |> Enum.filter(& &1.result.valid_input?)
    |> Enum.group_by(& &1.result.skeleton)
    |> Enum.sort_by(fn {_key, items} -> items |> hd() |> Map.fetch!(:index) end)
    |> Enum.filter(fn {_key, items} ->
      items |> Enum.map(& &1.input) |> Enum.uniq() |> length() >= 2
    end)
    |> Enum.map(fn {key, items} ->
      classes = oracle_classes(items)

      indexes = Enum.map(items, & &1.index)
      codes = Enum.sort([:skeleton_collision | classes])

      %Collision{
        key: key,
        indexes: indexes,
        inputs: Enum.map(items, & &1.input),
        class: List.first(classes) || :none,
        classes: classes,
        reasons: Enum.map(codes, &oracle_reason(&1, indexes, :critical)),
        unicode_version: "18.0.0"
      }
    end)
  end

  defp oracle_classes(items) do
    found =
      for {left, i} <- Enum.with_index(items),
          {right, j} <- Enum.with_index(items),
          i < j,
          reduce: MapSet.new() do
        found ->
          class = oracle_pair_class(left.result.domain.labels, right.result.domain.labels)
          if class == :none, do: found, else: MapSet.put(found, class)
      end

    Enum.filter(@precedence, &MapSet.member?(found, &1))
  end

  defp oracle_pair_class(left_labels, right_labels) do
    changed =
      Enum.zip(left_labels, right_labels)
      |> Enum.reject(fn {a, b} -> a.unicode == b.unicode end)

    classes =
      Enum.map(changed, fn {a, b} ->
        oracle_label_class(a.resolved_scripts, b.resolved_scripts)
      end)

    Enum.find(@precedence, :none, &(&1 in classes))
  end

  defp oracle_label_class(a, b) do
    cond do
      a == [] or b == [] -> :mixed_script_confusable
      a == :all or b == :all -> :single_script_confusable
      Enum.any?(a, &(&1 in b)) -> :single_script_confusable
      true -> :whole_script_confusable
    end
  end

  defp oracle_duplicates(inputs) do
    inputs
    |> Enum.with_index()
    |> Enum.filter(fn {input, _index} -> is_binary(input) end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.filter(fn {_input, indexes} -> length(indexes) >= 2 end)
    |> Enum.sort_by(fn {_input, indexes} -> hd(indexes) end)
    |> Enum.map(fn {input, indexes} ->
      %Duplicate{
        input: input,
        indexes: indexes,
        reasons: [oracle_reason(:exact_duplicate, indexes, :info)],
        unicode_version: "18.0.0"
      }
    end)
  end

  defp oracle_reason(code, indexes, severity) do
    messages = %{
      exact_duplicate: "Identifier is an exact duplicate",
      skeleton_collision: "Identifiers share a skeleton",
      single_script_confusable: "Identifiers are single-script confusables",
      mixed_script_confusable: "Identifiers are mixed-script confusables",
      whole_script_confusable: "Identifiers are whole-script confusables"
    }

    %Reason{
      code: code,
      severity: severity,
      message: Map.fetch!(messages, code),
      byte_offset: nil,
      codepoint_index: nil,
      details: %{indexes: indexes}
    }
  end

  defp combinations(_items, 0), do: [[]]
  defp combinations([], _size), do: []

  defp combinations([head | tail], size) do
    Enum.map(combinations(tail, size - 1), &[head | &1]) ++ combinations(tail, size)
  end

  defp permutations([]), do: [[]]

  defp permutations(items) do
    for item <- items, rest <- permutations(List.delete(items, item)), do: [item | rest]
  end

  defp trace_calls do
    receive do
      {:trace, _pid, :call, spec} -> [spec | trace_calls()]
    after
      0 -> []
    end
  end
end
