defmodule UnicodeSecurity.AuditTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.BatchItem
  alias UnicodeSecurity.Result

  test "audit preserves original index and binary check results" do
    inputs = ["m", <<255>>, "", String.duplicate("a", 4097), nil]
    items = UnicodeSecurity.audit(inputs, type: :tenant_slug) |> Enum.to_list()

    assert Enum.map(items, & &1.index) == [0, 1, 2, 3, 4]
    assert Enum.map(items, & &1.input) == inputs
    assert Enum.all?(items, &match?(%BatchItem{result: %Result{}}, &1))

    for item <- Enum.take(items, 4) do
      assert item.result == UnicodeSecurity.check(item.input, type: :tenant_slug)
    end

    result = List.last(items).result

    assert %{
             input: nil,
             type: :tenant_slug,
             policy: :default,
             verdict: :dangerous,
             valid_input?: false,
             skeleton: nil,
             scripts: nil,
             mixed_script?: nil,
             mixed_number?: nil,
             restriction_level: nil,
             domain: nil
           } = result

    assert [
             %{
               code: :invalid_item_type,
               severity: :critical,
               byte_offset: nil,
               codepoint_index: nil,
               details: %{actual_type: :atom}
             }
           ] = result.reasons
  end

  test "audit pulls only requested values and validates options before construction" do
    parent = self()

    source =
      Stream.iterate(0, &(&1 + 1))
      |> Stream.map(fn index ->
        send(parent, {:pulled, index})
        "m"
      end)

    stream = UnicodeSecurity.audit(source, type: :username)
    assert %Stream{} = stream
    refute_received {:pulled, _}
    assert Enum.map(Enum.take(stream, 2), & &1.index) == [0, 1]
    assert_received {:pulled, 0}
    assert_received {:pulled, 1}
    refute_received {:pulled, _}
    assert_raise ArgumentError, fn -> UnicodeSecurity.audit(source, []) end
    refute_received {:pulled, _}
  end

  test "nonbinary values use a closed descriptive type vocabulary" do
    port = :erlang.list_to_port(~c"#Port<0.0>")

    values = [
      nil,
      true,
      1,
      1.0,
      [],
      [1 | :tail],
      {},
      %{},
      %URI{},
      <<1::size(1)>>,
      fn -> :ok end,
      self(),
      port,
      make_ref()
    ]

    types = [
      :atom,
      :atom,
      :integer,
      :float,
      :list,
      :list,
      :tuple,
      :map,
      :map,
      :bitstring,
      :function,
      :pid,
      :port,
      :reference
    ]

    for preset <- [:strict, :default, :permissive] do
      results =
        UnicodeSecurity.audit(values, type: :username, policy: preset)
        |> Enum.map(& &1.result)

      assert Enum.map(results, fn result ->
               assert result.policy == preset and result.verdict == :dangerous
               assert [reason] = result.reasons
               assert reason.code == :invalid_item_type and reason.severity == :critical
               assert reason.message == "Batch item is not a binary"
               assert reason.byte_offset == nil and reason.codepoint_index == nil
               assert result.unicode_version == "18.0.0"
               reason.details.actual_type
             end) == types
    end
  end

  test "audit validates all check configuration branches before enumerating" do
    source = Stream.map(["a"], fn _ -> flunk("producer was read") end)

    for options <- [
          [],
          [type: :unknown],
          [type: :username, policy: :unknown],
          [type: :username, type: :username],
          [type: :username, unknown: :value],
          [type: :username, allowed_scripts: [:not_a_script]],
          [type: :username, denied_scripts: :latin],
          [type: :username, allowed_scripts: [:latin], denied_scripts: [:latin]]
        ],
        collection <- [[], source] do
      assert_raise ArgumentError, fn -> UnicodeSecurity.audit(collection, options) end
    end

    assert_raise ArgumentError, "expected an enumerable", fn ->
      UnicodeSecurity.audit(123, type: :username)
    end

    assert_raise ArgumentError, "unsupported or missing type", fn ->
      UnicodeSecurity.audit(123, [])
    end
  end

  test "audit applies domain checks through the shared policy" do
    [item] = UnicodeSecurity.audit(["BÜCHER。a."], type: :domain) |> Enum.to_list()
    assert item.result.valid_input?
    assert item.result.policy == :strict
    assert item.result.domain.ascii == "xn--bcher-kva.a."
    assert item.result.skeleton != nil
  end

  test "audit retains term identity, map entries, and producer exceptions" do
    value = %{key: 1}
    [item] = UnicodeSecurity.audit([value], type: :organization_name) |> Enum.to_list()
    assert item.input == value
    assert item.result.input == value
    assert item.result.policy == :permissive

    assert item.result.reasons == [
             %UnicodeSecurity.Reason{
               code: :invalid_item_type,
               severity: :critical,
               message: "Batch item is not a binary",
               byte_offset: nil,
               codepoint_index: nil,
               details: %{actual_type: :map}
             }
           ]

    [entry] = UnicodeSecurity.audit(%{a: "m"}, type: :username) |> Enum.to_list()
    assert entry.input == {:a, "m"}
    assert hd(entry.result.reasons).details == %{actual_type: :tuple}

    stream =
      UnicodeSecurity.audit(Stream.map([1], fn _ -> raise "producer error" end), type: :username)

    assert_raise RuntimeError, "producer error", fn -> Enum.to_list(stream) end
  end

  test "audit uses type defaults and respects script overrides" do
    for {type, preset} <- [
          {:username, :default},
          {:tenant_slug, :default},
          {:organization_name, :permissive}
        ] do
      [item] = UnicodeSecurity.audit(["a"], type: type) |> Enum.to_list()
      assert item.result.type == type
      assert item.result.policy == preset
    end

    [disallowed] =
      UnicodeSecurity.audit(["a"], type: :username, allowed_scripts: [:greek])
      |> Enum.to_list()

    [denied] =
      UnicodeSecurity.audit(["a"], type: :username, denied_scripts: [:latin])
      |> Enum.to_list()

    assert Enum.any?(disallowed.result.reasons, &(&1.code == :disallowed_script))
    assert Enum.any?(denied.result.reasons, &(&1.code == :denied_script))
  end

  test "each enumeration starts indexing at zero" do
    stream = UnicodeSecurity.audit(["m", "n"], type: :username)
    assert Enum.map(stream, & &1.index) == [0, 1]
    assert Enum.map(stream, & &1.index) == [0, 1]
  end

  property "audit and check agree for arbitrary binary inputs" do
    check all(
            input <- binary(max_length: 100),
            type <- member_of([:username, :tenant_slug, :organization_name]),
            options <-
              member_of([
                [],
                [policy: :strict],
                [policy: :permissive],
                [allowed_scripts: [:latin]],
                [denied_scripts: [:latin]]
              ]),
            max_runs: 50
          ) do
      options = [{:type, type} | options]
      [item] = UnicodeSecurity.audit([input], options) |> Enum.to_list()
      assert item.result == UnicodeSecurity.check(input, options)
    end
  end
end
