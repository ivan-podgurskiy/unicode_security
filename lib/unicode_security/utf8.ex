defmodule UnicodeSecurity.Utf8 do
  @moduledoc false

  alias UnicodeSecurity.InvalidInputError

  @spec decode!(binary()) :: [{0..0x10FFFF, non_neg_integer()}]
  def decode!(input) when is_binary(input) do
    if byte_size(input) > 4096 do
      raise InvalidInputError, reason: :input_too_long, byte_offset: 4096
    end

    decode(input, 0, [])
  end

  defp decode(<<>>, _offset, acc), do: Enum.reverse(acc)

  defp decode(<<scalar, rest::binary>>, offset, acc) when scalar < 0x80,
    do: decode(rest, offset + 1, [{scalar, offset} | acc])

  defp decode(<<a, b, rest::binary>>, offset, acc)
       when a in 0xC2..0xDF and b in 0x80..0xBF do
    scalar = (a - 0xC0) * 64 + b - 0x80
    decode(rest, offset + 2, [{scalar, offset} | acc])
  end

  defp decode(<<a, b, c, rest::binary>>, offset, acc)
       when a in 0xE0..0xEF and b in 0x80..0xBF and c in 0x80..0xBF and
              (a != 0xE0 or b >= 0xA0) and (a != 0xED or b < 0xA0) do
    scalar = (a - 0xE0) * 4096 + (b - 0x80) * 64 + c - 0x80
    decode(rest, offset + 3, [{scalar, offset} | acc])
  end

  defp decode(<<a, b, c, d, rest::binary>>, offset, acc)
       when a in 0xF0..0xF4 and b in 0x80..0xBF and c in 0x80..0xBF and d in 0x80..0xBF and
              (a != 0xF0 or b >= 0x90) and (a != 0xF4 or b < 0x90) do
    scalar = (a - 0xF0) * 262_144 + (b - 0x80) * 4096 + (c - 0x80) * 64 + d - 0x80
    decode(rest, offset + 4, [{scalar, offset} | acc])
  end

  defp decode(_input, offset, _acc),
    do: raise(InvalidInputError, reason: :invalid_utf8, byte_offset: offset)
end
