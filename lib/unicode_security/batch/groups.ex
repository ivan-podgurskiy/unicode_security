defmodule UnicodeSecurity.Batch.Groups do
  @moduledoc """
  Accumulates eager batch outputs in source enumeration order.

  Exact binary identity and computed skeleton keys have separate indexes.
  Individual results are retained unchanged.
  """

  alias UnicodeSecurity.Batch.Classes
  alias UnicodeSecurity.{BatchItem, BatchResult, Collision, Duplicate, Pair, Policy, Reason, Utf8}

  @type state :: %{
          results_rev: [BatchItem.t()],
          by_input: %{optional(binary()) => [non_neg_integer()]},
          input_order_rev: [binary()],
          by_key: %{optional(binary()) => map()},
          key_order_rev: [binary()]
        }

  @doc "Creates empty ordered grouping state."
  @spec new() :: state()
  def new do
    %{results_rev: [], by_input: %{}, input_order_rev: [], by_key: %{}, key_order_rev: []}
  end

  @doc "Adds one indexed item without changing its result."
  @spec add(state(), BatchItem.t()) :: state()
  def add(state, %BatchItem{} = item) do
    state = %{state | results_rev: [item | state.results_rev]}

    if is_binary(item.input) do
      state
      |> add_input(item)
      |> add_key(item)
    else
      state
    end
  end

  @doc "Finalizes ordered duplicate and collision records."
  @spec finish(state(), Policy.t()) :: BatchResult.t()
  def finish(state, policy) do
    %BatchResult{
      results: Enum.reverse(state.results_rev),
      duplicates: finish_duplicates(state, policy),
      collisions: finish_collisions(state, policy),
      unicode_version: UnicodeSecurity.unicode_version()
    }
  end

  defp add_input(state, item) do
    seen? = Map.has_key?(state.by_input, item.input)
    by_input = Map.update(state.by_input, item.input, [item.index], &[item.index | &1])

    %{
      state
      | by_input: by_input,
        input_order_rev:
          if(seen?, do: state.input_order_rev, else: [item.input | state.input_order_rev])
    }
  end

  defp add_key(state, %BatchItem{input: input, index: index, result: result}) do
    if result.valid_input? and is_binary(result.skeleton) do
      key = result.skeleton
      seen? = Map.has_key?(state.by_key, key)

      bucket =
        Map.get(state.by_key, key, %{members_rev: [], originals: MapSet.new(), signatures: %{}})

      signatures =
        if MapSet.member?(bucket.originals, input) do
          bucket.signatures
        else
          facts = input |> Utf8.decode!() |> Pair.from_decoded(key)
          Classes.add(bucket.signatures, facts.resolved, facts.nfd)
        end

      bucket = %{
        members_rev: [{index, input} | bucket.members_rev],
        originals: MapSet.put(bucket.originals, input),
        signatures: signatures
      }

      %{
        state
        | by_key: Map.put(state.by_key, key, bucket),
          key_order_rev: if(seen?, do: state.key_order_rev, else: [key | state.key_order_rev])
      }
    else
      state
    end
  end

  defp finish_duplicates(state, policy) do
    state.input_order_rev
    |> Enum.reverse()
    |> Enum.flat_map(fn input ->
      indexes = state.by_input |> Map.fetch!(input) |> Enum.reverse()

      if length(indexes) >= 2 do
        [
          %Duplicate{
            input: input,
            indexes: indexes,
            reasons: [reason(:exact_duplicate, indexes, policy)],
            unicode_version: UnicodeSecurity.unicode_version()
          }
        ]
      else
        []
      end
    end)
  end

  defp finish_collisions(state, policy) do
    state.key_order_rev
    |> Enum.reverse()
    |> Enum.flat_map(fn key ->
      bucket = Map.fetch!(state.by_key, key)

      if MapSet.size(bucket.originals) >= 2 do
        members = Enum.reverse(bucket.members_rev)
        {indexes, inputs} = Enum.unzip(members)
        classes = Classes.finish(bucket.signatures)
        codes = Enum.sort([:skeleton_collision | classes])

        [
          %Collision{
            key: key,
            indexes: indexes,
            inputs: inputs,
            class: List.first(classes) || :none,
            classes: classes,
            reasons: Enum.map(codes, &reason(&1, indexes, policy)),
            unicode_version: UnicodeSecurity.unicode_version()
          }
        ]
      else
        []
      end
    end)
  end

  @messages %{
    exact_duplicate: "Identifier is an exact duplicate",
    skeleton_collision: "Identifiers share a skeleton",
    single_script_confusable: "Identifiers are single-script confusables",
    mixed_script_confusable: "Identifiers are mixed-script confusables",
    whole_script_confusable: "Identifiers are whole-script confusables"
  }

  defp reason(code, indexes, policy) do
    %Reason{
      code: code,
      severity: Policy.severity(policy.preset, code),
      message: Map.fetch!(@messages, code),
      byte_offset: nil,
      codepoint_index: nil,
      details: %{indexes: indexes}
    }
  end
end
