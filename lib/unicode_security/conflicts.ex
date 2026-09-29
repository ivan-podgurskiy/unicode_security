defmodule UnicodeSecurity.Conflicts do
  @moduledoc false

  alias UnicodeSecurity.{
    ComparisonOptions,
    Conflict,
    Confusables,
    Domain,
    Pair,
    SkeletonTrace,
    Utf8
  }

  @spec conflict_key(binary(), term()) :: binary()
  def conflict_key(input, options) do
    case ComparisonOptions.resolve!(options, :required) do
      :domain -> input |> Domain.validate!() |> Domain.key()
      _type -> Confusables.skeleton(input)
    end
  end

  @spec conflicts?(binary(), Enumerable.t(), term()) :: boolean()
  def conflicts?(input, existing, options) do
    type = ComparisonOptions.resolve!(options, :required)
    key = conflict_key_for(input, type)
    validate_enumerable!(existing)

    case type do
      :domain -> Enum.any?(existing, &(domain_key(&1) == key))
      _type -> Enum.any?(existing, &(Confusables.skeleton(&1) == key))
    end
  end

  @spec conflicts(binary(), Enumerable.t(), term()) :: [Conflict.t()]
  def conflicts(input, existing, options) do
    case ComparisonOptions.resolve!(options, :required) do
      :domain -> domain_conflicts(input, existing)
      _type -> generic_conflicts(input, existing)
    end
  end

  defp generic_conflicts(input, existing) do
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

  defp domain_conflicts(input, existing) do
    candidate = Domain.validate!(input)
    key = Domain.key(candidate)
    validate_enumerable!(existing)

    {matches_rev, _left_cache} =
      existing
      |> Stream.with_index()
      |> Enum.reduce({[], nil}, fn {existing_value, index}, {matches_rev, left_cache} ->
        right = Domain.validate!(existing_value)

        if Domain.key(right) == key do
          domain_matched(
            input,
            key,
            candidate,
            existing_value,
            right,
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

  defp domain_matched(
         input,
         key,
         candidate,
         existing_value,
         right,
         index,
         matches_rev,
         left_cache
       ) do
    {left_facts, left_mappings} = left_cache || domain_prepare_traced(candidate, key, :left)
    {right_facts, right_mappings} = domain_prepare_traced(right, key, :right)

    comparison =
      left_facts
      |> Domain.Comparison.compare_prepared(right_facts)
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

  defp domain_prepare_traced(validated, key, side) do
    facts = Domain.prepare(validated, key)
    {^key, mappings} = Domain.Comparison.trace(facts, side)
    {facts, mappings}
  end

  defp conflict_key_for(input, :domain), do: domain_key(input)
  defp conflict_key_for(input, _type), do: Confusables.skeleton(input)

  defp domain_key(input), do: input |> Domain.validate!() |> Domain.key()

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
