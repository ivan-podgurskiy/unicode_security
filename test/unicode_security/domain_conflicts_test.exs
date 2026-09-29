defmodule UnicodeSecurity.DomainConflictsTest do
  use ExUnit.Case, async: false

  alias UnicodeSecurity.{Conflict, Domain, InvalidDomainError, InvalidInputError}

  test "domain keys normalize IDNA and ignore one final root" do
    assert UnicodeSecurity.conflict_key("bücher.a", type: :domain) ==
             UnicodeSecurity.conflict_key("XN--BCHER-KVA.a.", type: :domain)

    assert UnicodeSecurity.conflict_key("a.", type: :domain) == "a"
    assert UnicodeSecurity.conflict_key("a۰b.c", type: :domain) == "a%2Eb.c"
  end

  test "predicate halts before producer or invalid tail" do
    tail = Stream.map([:tail], fn _ -> raise "tail visited" end)
    existing = Stream.concat(["xn--bcher-kva.a"], tail)
    assert UnicodeSecurity.conflicts?("bücher.a", existing, type: :domain)
    assert UnicodeSecurity.conflicts?("a", ["A", "xn--abc-"], type: :domain)
  end

  test "IDNA-equivalent spellings collide without confusable class" do
    [hit] = UnicodeSecurity.conflicts("a", ["A."], type: :domain)
    assert %Conflict{} = hit
    assert {hit.index, hit.code, hit.key} == {0, :skeleton_collision, "a"}
    assert hit.comparison.class == :none
    assert hit.comparison == UnicodeSecurity.compare("a", "A.", type: :domain)

    assert_raise InvalidDomainError, fn ->
      UnicodeSecurity.conflicts?("a", ["b", "xn--abc-"], type: :domain)
    end
  end

  test "all hits retain source indexes, order, and exact duplicate precedence" do
    hits = UnicodeSecurity.conflicts("а.a", ["x.a", "a.a", "а.a", "a.a."], type: :domain)

    assert Enum.map(hits, &{&1.index, &1.code}) == [
             {1, :whole_script_confusable},
             {2, :exact_duplicate},
             {3, :whole_script_confusable}
           ]

    for hit <- hits do
      assert hit.comparison == UnicodeSecurity.compare("а.a", hit.existing, type: :domain)
      assert hit.unicode_version == UnicodeSecurity.unicode_version()
    end
  end

  test "candidate validation precedes enumerable protocol and visited values fail" do
    assert_raise InvalidDomainError, fn ->
      UnicodeSecurity.conflicts?("xn--abc-", nil, type: :domain)
    end

    assert_raise ArgumentError, "expected an enumerable", fn ->
      UnicodeSecurity.conflicts("a", nil, type: :domain)
    end

    assert_raise InvalidDomainError, fn ->
      UnicodeSecurity.conflicts("a", ["a", "xn--abc-"], type: :domain)
    end

    for input <- [<<255>>, String.duplicate("a", 4097)] do
      assert_raise InvalidInputError, fn ->
        UnicodeSecurity.conflict_key(input, type: :domain)
      end
    end

    assert_raise ArgumentError, fn ->
      UnicodeSecurity.conflicts?(<<255>>, nil, type: :domain, policy: :default)
    end
  end

  test "empty collections and producer errors preserve enumerable behavior" do
    refute UnicodeSecurity.conflicts?("a", [], type: :domain)
    assert UnicodeSecurity.conflicts("a", [], type: :domain) == []
    refute UnicodeSecurity.conflicts?("a", %{}, type: :domain)
    assert UnicodeSecurity.conflicts("a", %{}, type: :domain) == []

    source = Stream.map([0], fn _ -> raise "producer failed" end)

    for operation <- [&UnicodeSecurity.conflicts?/3, &UnicodeSecurity.conflicts/3] do
      assert_raise RuntimeError, "producer failed", fn ->
        operation.("a", source, type: :domain)
      end
    end
  end

  test "misses avoid rich facts and hits cache candidate facts and evidence" do
    assert traced_calls(["b", "c"]) == {0, 0, 0}
    assert traced_calls(["b", "A", "a", "a."]) == {3, 4, 4}
  end

  defp traced_calls(existing) do
    parent = self()

    worker =
      spawn(fn ->
        receive do
          :run ->
            send(parent, {:result, UnicodeSecurity.conflicts("a", existing, type: :domain)})
            receive do: (:stop -> :ok)
        end
      end)

    :erlang.trace_pattern({Domain, :prepare, 2}, true, [])
    :erlang.trace_pattern({Domain.Comparison, :trace, 2}, true, [])
    :erlang.trace(worker, true, [:call, {:tracer, parent}])

    try do
      send(worker, :run)
      assert_receive {:result, hits}
      ref = :erlang.trace_delivered(worker)
      assert_receive {:trace_delivered, ^worker, ^ref}

      calls = drain_calls(worker, [])

      {length(hits), Enum.count(calls, &match?({Domain, :prepare, _}, &1)),
       Enum.count(calls, &match?({Domain.Comparison, :trace, _}, &1))}
    after
      :erlang.trace(worker, false, [:all])
      :erlang.trace_pattern({Domain, :prepare, 2}, false, [])
      :erlang.trace_pattern({Domain.Comparison, :trace, 2}, false, [])
      send(worker, :stop)
    end
  end

  defp drain_calls(worker, calls) do
    receive do
      {:trace, ^worker, :call, function} -> drain_calls(worker, [function | calls])
    after
      0 -> calls
    end
  end
end
