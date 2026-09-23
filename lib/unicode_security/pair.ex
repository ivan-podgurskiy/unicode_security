defmodule UnicodeSecurity.Pair do
  @moduledoc false

  alias UnicodeSecurity.{
    Comparison,
    ComparisonOptions,
    Confusables,
    Normalization,
    Scripts,
    SkeletonTrace,
    Utf8
  }

  @type prepared :: %{
          decoded: [{non_neg_integer(), non_neg_integer()}],
          scalars: [non_neg_integer()],
          nfd: [non_neg_integer()],
          skeleton: binary(),
          scripts: [atom()],
          resolved: Comparison.resolved_scripts()
        }

  @spec prepare(binary()) :: prepared()
  def prepare(input) do
    decoded = Utf8.decode!(input)
    scalars = Enum.map(decoded, &elem(&1, 0))
    from_decoded(decoded, Confusables.skeleton_scalars(scalars))
  end

  @spec from_decoded([{non_neg_integer(), non_neg_integer()}], binary()) :: prepared()
  def from_decoded(decoded, skeleton) do
    scalars = Enum.map(decoded, &elem(&1, 0))
    resolved = Scripts.resolved_set(scalars)

    %{
      decoded: decoded,
      scalars: scalars,
      nfd: Normalization.nfd_scalars(scalars),
      skeleton: skeleton,
      scripts: Scripts.scripts_scalars(scalars),
      resolved: if(resolved == :all, do: :all, else: resolved |> MapSet.to_list() |> Enum.sort())
    }
  end

  @spec same_skeleton?(binary(), binary()) :: boolean()
  def same_skeleton?(left, right) do
    left_key = Confusables.skeleton(left)
    right_key = Confusables.skeleton(right)
    left_key == right_key
  end

  @spec confusable?(binary(), binary()) :: boolean()
  def confusable?(left, right) do
    left_facts = prepare(left)
    right_facts = prepare(right)
    left_facts.skeleton == right_facts.skeleton and left_facts.nfd != right_facts.nfd
  end

  @spec compare(binary(), binary(), term()) :: Comparison.t()
  def compare(left, right, options \\ []) do
    ComparisonOptions.resolve!(options, :optional)
    left_facts = prepare(left)
    right_facts = prepare(right)
    comparison = compare_prepared(left_facts, right_facts)
    {_left_skeleton, left_mappings} = SkeletonTrace.trace(left_facts.decoded, :left)
    {_right_skeleton, right_mappings} = SkeletonTrace.trace(right_facts.decoded, :right)
    %{comparison | mappings: left_mappings ++ right_mappings}
  end

  @spec classify_sets(Comparison.resolved_scripts(), Comparison.resolved_scripts()) ::
          :single_script_confusable | :whole_script_confusable | :mixed_script_confusable
  def classify_sets([], _right), do: :mixed_script_confusable
  def classify_sets(_left, []), do: :mixed_script_confusable
  def classify_sets(:all, _right), do: :single_script_confusable
  def classify_sets(_left, :all), do: :single_script_confusable

  def classify_sets(left, right) do
    if Enum.any?(left, &(&1 in right)),
      do: :single_script_confusable,
      else: :whole_script_confusable
  end

  @spec compare_prepared(prepared(), prepared()) :: Comparison.t()
  def compare_prepared(left, right) do
    equal_key? = left.skeleton == right.skeleton
    canonical? = left.nfd == right.nfd
    confusable? = equal_key? and not canonical?

    %Comparison{
      confusable?: confusable?,
      same_skeleton?: equal_key?,
      class: if(confusable?, do: classify_sets(left.resolved, right.resolved), else: :none),
      canonically_equivalent?: canonical?,
      left_skeleton: left.skeleton,
      right_skeleton: right.skeleton,
      left_scripts: left.scripts,
      right_scripts: right.scripts,
      left_resolved_scripts: left.resolved,
      right_resolved_scripts: right.resolved,
      unicode_version: UnicodeSecurity.unicode_version()
    }
  end
end
