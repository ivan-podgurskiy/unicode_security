defmodule UnicodeSecurity.Conflicts do
  @moduledoc false

  alias UnicodeSecurity.{ComparisonOptions, Conflict, Confusables, Pair, SkeletonTrace, Utf8}

  @spec conflict_key(binary(), term()) :: binary()
  def conflict_key(input, options) do
    ComparisonOptions.resolve!(options, :required)
    Confusables.skeleton(input)
  end

  @spec conflicts?(binary(), Enumerable.t(), term()) :: boolean()
  def conflicts?(input, existing, options) do
    key = conflict_key(input, options)
    validate_enumerable!(existing)
    Enum.any?(existing, &(Confusables.skeleton(&1) == key))
  end

  @spec conflicts(binary(), Enumerable.t(), term()) :: [Conflict.t()]
  def conflicts(input, existing, options) do
    ComparisonOptions.resolve!(options, :required)
    candidate_decoded = Utf8.decode!(input)
    key = candidate_decoded |> Enum.map(&elem(&1, 0)) |> Confusables.skeleton_scalars()
    validate_enumerable!(existing)

    {matches_rev, _left_cache} =
      existing
      |> Stream.with_index()
      |> Enum.reduce({[], nil}, fn {existing_value, index}, {matches_rev, left_cache} ->
        right_decoded = Utf8.decode!(existing_value)
        right_key = right_decoded |> Enum.map(&elem(&1, 0)) |> Confusables.skeleton_scalars()

        if right_key == key do
          matched(
            input,
            key,
            candidate_decoded,
            existing_value,
            right_decoded,
            index,
            matches_rev,
            left_cache
          )
        else
          {matches_rev, left_cache}
        end
      end)

    Enum.reverse(matches_rev)
  end

  defp matched(
         input,
         key,
         candidate_decoded,
         existing_value,
         right_decoded,
         index,
         matches_rev,
         left_cache
       ) do
    {left_facts, left_mappings} = left_cache || prepare_traced(candidate_decoded, key, :left)
    {right_facts, right_mappings} = prepare_traced(right_decoded, key, :right)

    comparison =
      left_facts
      |> Pair.compare_prepared(right_facts)
      |> Map.put(:mappings, left_mappings ++ right_mappings)

    code =
      cond do
        input == existing_value -> :exact_duplicate
        comparison.confusable? -> comparison.class
        true -> :skeleton_collision
      end

    hit = %Conflict{
      input: input,
      existing: existing_value,
      index: index,
      key: key,
      comparison: comparison,
      code: code,
      unicode_version: UnicodeSecurity.unicode_version()
    }

    {[hit | matches_rev], {left_facts, left_mappings}}
  end

  defp prepare_traced(decoded, key, side) do
    facts = Pair.from_decoded(decoded, key)
    {^key, mappings} = SkeletonTrace.trace(decoded, side)
    {facts, mappings}
  end

  defp validate_enumerable!(enumerable) do
    if Enumerable.impl_for(enumerable) == nil,
      do: raise(ArgumentError, "expected an enumerable")

    :ok
  end
end
