defmodule UnicodeSecurity.Domain.Classes do
  @moduledoc """
  Correlated Unicode-label facts for one domain skeleton bucket.

  Canonical vectors are deduplicated within each resolved-script signature.
  A class exists only when a pair has an unequal label at that class's rank
  while every potentially stronger label is equal.
  """

  alias UnicodeSecurity.{Collision, Comparison, Pair}

  @classes [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable]
  @ranks %{single_script_confusable: 1, whole_script_confusable: 2, mixed_script_confusable: 3}

  @type signature :: [Comparison.resolved_scripts()]
  @type vector :: [binary()]
  @type state :: %{optional(signature()) => MapSet.t(vector())}

  @doc "Adds one validated Unicode-label vector to its signature group."
  @spec add(state(), signature(), vector()) :: state()
  def add(groups, signature, canonical) do
    Map.update(groups, signature, MapSet.new([canonical]), &MapSet.put(&1, canonical))
  end

  @doc "Returns realized primary classes in risk order."
  @spec finish(state()) :: [Collision.class()]
  def finish(groups) do
    entries =
      groups
      |> Enum.map(fn {signature, values} ->
        {signature, Enum.map(values, &List.to_tuple/1)}
      end)
      |> Enum.with_index()

    found =
      for {{left_signature, left_values}, i} <- entries,
          {{right_signature, right_values}, j} <- entries,
          i <= j,
          target <- @classes,
          target_exists?(left_signature, left_values, right_signature, right_values, target),
          reduce: MapSet.new() do
        found -> MapSet.put(found, target)
      end

    Enum.filter(@classes, &MapSet.member?(found, &1))
  end

  defp target_exists?(left_signature, left_values, right_signature, right_values, target) do
    rank = Map.fetch!(@ranks, target)

    potential =
      Enum.zip(left_signature, right_signature)
      |> Enum.map(fn {a, b} -> Map.fetch!(@ranks, Pair.classify_sets(a, b)) end)

    stronger =
      potential
      |> Enum.with_index()
      |> Enum.filter(fn {potential_rank, _index} -> potential_rank > rank end)
      |> Enum.map(&elem(&1, 1))

    equal =
      potential
      |> Enum.with_index()
      |> Enum.filter(fn {potential_rank, _index} -> potential_rank == rank end)
      |> Enum.map(&elem(&1, 1))

    if equal == [] do
      false
    else
      left = projections(left_values, stronger, equal)
      right = projections(right_values, stronger, equal)

      Enum.any?(left, fn {key, left_targets} ->
        matching_projection?(key, left_targets, right)
      end)
    end
  end

  defp projections(values, stronger, equal) do
    Enum.reduce(values, %{}, fn value, acc ->
      key = Enum.map(stronger, &elem(value, &1))
      target = Enum.map(equal, &elem(value, &1))

      Map.update(acc, key, [target], &remember_target(&1, target))
    end)
  end

  defp different_targets?(left, right) do
    Enum.any?(left, fn value -> Enum.any?(right, &(&1 != value)) end)
  end

  defp matching_projection?(key, left_targets, right) do
    case Map.fetch(right, key) do
      :error -> false
      {:ok, right_targets} -> different_targets?(left_targets, right_targets)
    end
  end

  defp remember_target(seen, target) do
    if target in seen, do: seen, else: Enum.take([target | seen], 2)
  end
end
