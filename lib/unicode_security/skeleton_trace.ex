defmodule UnicodeSecurity.SkeletonTrace do
  @moduledoc false

  alias UnicodeSecurity.{Bidi, Confusables, Normalization}

  @spec trace([{0..0x10FFFF, non_neg_integer()}], :left | :right) ::
          {binary(), [UnicodeSecurity.Comparison.mapping()]}
  def trace(decoded, side) when side in [:left, :right] do
    final =
      decoded
      |> Enum.map(&elem(&1, 0))
      |> Bidi.reorder_with_indexes()
      |> Normalization.nfd_tagged()
      |> Enum.flat_map(fn {scalar, origin} ->
        Enum.map(Confusables.prototype(scalar), &{&1, origin})
      end)
      |> Normalization.nfd_tagged()

    skeleton =
      final |> Enum.map(fn {scalar, _origin} -> <<scalar::utf8>> end) |> IO.iodata_to_binary()

    contributions =
      final
      |> Enum.with_index()
      |> Enum.reduce(%{}, fn {{scalar, origin}, target_index}, acc ->
        Map.update(acc, origin, [{target_index, scalar}], &[{target_index, scalar} | &1])
      end)

    mappings =
      decoded
      |> Enum.with_index()
      |> Enum.map(fn {{scalar, byte_offset}, source_index} ->
        targets = contributions |> Map.get(source_index, []) |> Enum.reverse()

        %{
          side: side,
          byte_offset: byte_offset,
          byte_length: byte_size(<<scalar::utf8>>),
          codepoint_index: source_index,
          codepoint_count: 1,
          codepoints: [scalar],
          skeleton_spans: spans(targets),
          mapping:
            targets |> Enum.map(fn {_index, code} -> <<code::utf8>> end) |> IO.iodata_to_binary()
        }
      end)

    {skeleton, mappings}
  end

  defp spans(targets) do
    targets
    |> Enum.reduce([], fn {index, _scalar}, acc ->
      case acc do
        [%{codepoint_index: start, codepoint_count: count} = head | rest]
        when index == start + count ->
          [%{head | codepoint_count: count + 1} | rest]

        _ ->
          [%{codepoint_index: index, codepoint_count: 1} | acc]
      end
    end)
    |> Enum.reverse()
  end
end
