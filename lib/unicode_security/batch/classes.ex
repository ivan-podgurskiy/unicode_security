defmodule UnicodeSecurity.Batch.Classes do
  @moduledoc """
  Compressed canonical and resolved-script facts for one skeleton bucket.

  At most two distinct NFD representatives per resolved signature suffice to
  establish whether a canonically distinct pair exists for any two signatures.
  """

  alias UnicodeSecurity.Pair

  @type signature :: :all | [atom()]
  @type summaries :: %{optional(signature()) => [[non_neg_integer()]]}

  @doc "Adds one canonical value to its resolved-script signature."
  @spec add(summaries(), signature(), [non_neg_integer()]) :: summaries()
  def add(signatures, resolved, canonical) do
    Map.update(signatures, resolved, [canonical], fn representatives ->
      [canonical | representatives] |> Enum.uniq() |> Enum.take(2)
    end)
  end

  @doc "Returns present confusable classes in risk precedence order."
  @spec finish(summaries()) :: [UnicodeSecurity.Collision.class()]
  def finish(signatures) do
    entries = signatures |> Map.to_list() |> Enum.with_index()

    found =
      for {{left, left_values}, i} <- entries,
          {{right, right_values}, j} <- entries,
          i <= j,
          distinct_canonical_pair?(left_values, right_values),
          reduce: MapSet.new() do
        classes -> MapSet.put(classes, Pair.classify_sets(left, right))
      end

    Enum.filter(
      [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable],
      &MapSet.member?(found, &1)
    )
  end

  defp distinct_canonical_pair?([left], [right]), do: left != right
  defp distinct_canonical_pair?(_left, _right), do: true
end
