defmodule UnicodeSecurity.Domain.Comparison do
  @moduledoc false

  alias UnicodeSecurity.{Comparison, Domain, Pair}
  alias UnicodeSecurity.Domain.Key

  @spec compare_prepared(Domain.prepared(), Domain.prepared()) :: Comparison.t()
  def compare_prepared(left, right) do
    same_key? = left.skeleton == right.skeleton
    confusable? = same_key? and left.unicode_vector != right.unicode_vector

    classes =
      if confusable? do
        Enum.zip(left.labels, right.labels)
        |> Enum.reject(fn {a, b} -> a.unicode == b.unicode end)
        |> Enum.map(fn {a, b} -> Pair.classify_sets(a.resolved, b.resolved) end)
      else
        []
      end

    class =
      Enum.find(
        [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable],
        :none,
        &(&1 in classes)
      )

    %Comparison{
      confusable?: confusable?,
      same_skeleton?: same_key?,
      class: class,
      canonically_equivalent?: left.nfd == right.nfd,
      left_skeleton: left.skeleton,
      right_skeleton: right.skeleton,
      left_scripts: left.scripts,
      right_scripts: right.scripts,
      left_resolved_scripts: left.resolved,
      right_resolved_scripts: right.resolved,
      unicode_version: UnicodeSecurity.unicode_version()
    }
  end

  @spec trace(Domain.prepared(), :left | :right) :: {binary(), [Comparison.mapping()]}
  def trace(facts, side) do
    labels = List.to_tuple(facts.labels)
    last_index = tuple_size(labels) - 1

    {chunks, records, _index} =
      Enum.reduce(facts.units, {[], [], 0}, fn unit, {chunks, records, target_index} ->
        trace_unit(unit, labels, last_index, side, chunks, records, target_index)
      end)

    {chunks |> Enum.reverse() |> IO.iodata_to_binary(), Enum.reverse(records)}
  end

  defp trace_unit(unit, labels, last_index, side, chunks, records, target_index) do
    contribution = contribution(unit, labels, last_index)

    if unit.byte_length == 0 do
      {chunks, records, target_index}
    else
      count = contribution |> String.to_charlist() |> length()

      spans =
        if count == 0,
          do: [],
          else: [%{codepoint_index: target_index, codepoint_count: count}]

      record = %{
        side: side,
        byte_offset: unit.byte_offset,
        byte_length: unit.byte_length,
        codepoint_index: unit.codepoint_index,
        codepoint_count: unit.codepoint_count,
        codepoints: unit.codepoints,
        skeleton_spans: spans,
        mapping: contribution
      }

      {[contribution | chunks], [record | records], target_index + count}
    end
  end

  defp contribution(%{kind: :label, label_index: index}, labels, last_index)
       when index <= last_index,
       do: labels |> elem(index) |> Map.fetch!(:skeleton) |> Key.escape()

  defp contribution(%{kind: :label}, _labels, _last_index), do: ""

  defp contribution(%{kind: :separator, label_index: index}, _labels, last_index)
       when index < last_index,
       do: "."

  defp contribution(%{kind: :separator}, _labels, _last_index), do: ""
end
