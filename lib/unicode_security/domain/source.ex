defmodule UnicodeSecurity.Domain.Source do
  @moduledoc false

  @type unit :: %{
          kind: :label | :separator,
          label_index: non_neg_integer(),
          input: binary(),
          byte_offset: non_neg_integer(),
          byte_length: non_neg_integer(),
          codepoint_index: non_neg_integer(),
          codepoint_count: non_neg_integer(),
          codepoints: [non_neg_integer()]
        }

  @separators [?., 0x3002, 0xFF0E, 0xFF61]

  @spec units(binary(), [{non_neg_integer(), non_neg_integer()}]) :: [unit()]
  def units(input, decoded), do: collect(decoded, input, 0, 0, 0, [], [])

  defp collect([], input, start_byte, start_cp, index, current, acc) do
    label = label(input, start_byte, byte_size(input), start_cp, current, index)
    Enum.reverse([label | acc])
  end

  defp collect([{scalar, offset} | rest], input, start_byte, start_cp, index, current, acc)
       when scalar in @separators do
    label = label(input, start_byte, offset, start_cp, current, index)
    cp_index = start_cp + length(current)
    separator = <<scalar::utf8>>

    separator_unit = %{
      kind: :separator,
      label_index: index,
      input: separator,
      byte_offset: offset,
      byte_length: byte_size(separator),
      codepoint_index: cp_index,
      codepoint_count: 1,
      codepoints: [scalar]
    }

    collect(rest, input, offset + byte_size(separator), cp_index + 1, index + 1, [], [
      separator_unit,
      label | acc
    ])
  end

  defp collect([{scalar, _offset} | rest], input, start_byte, start_cp, index, current, acc),
    do: collect(rest, input, start_byte, start_cp, index, [scalar | current], acc)

  defp label(input, start_byte, end_byte, start_cp, reversed, index) do
    %{
      kind: :label,
      label_index: index,
      input: binary_part(input, start_byte, end_byte - start_byte),
      byte_offset: start_byte,
      byte_length: end_byte - start_byte,
      codepoint_index: start_cp,
      codepoint_count: length(reversed),
      codepoints: Enum.reverse(reversed)
    }
  end
end
