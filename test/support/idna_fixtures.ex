defmodule UnicodeSecurity.Test.IdnaFixtures do
  @moduledoc false

  @spec parse!(binary()) :: [map()]
  def parse!(text) do
    text
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.flat_map(fn {line, number} ->
      body = line |> String.split("#", parts: 2) |> hd() |> trim_ascii()

      if body == "" do
        []
      else
        [parse_line!(body, number)]
      end
    end)
  end

  defp parse_line!(line, number) do
    case String.split(line, ";", trim: false) do
      [source, unicode, unicode_status, ascii, ascii_status, transitional, transitional_status] ->
        source = parse_text!(source, number)
        unicode = inherit_text(unicode, source, number)
        unicode_status = parse_status!(unicode_status, [], number)
        ascii = inherit_text(ascii, unicode, number)
        ascii_status = parse_status!(ascii_status, unicode_status, number)
        transitional = inherit_text(transitional, ascii, number)
        _transitional_status = parse_status!(transitional_status, ascii_status, number)
        _ = transitional

        %{
          line: number,
          source: source,
          unicode: unicode,
          unicode_status: unicode_status,
          ascii: ascii,
          ascii_status: ascii_status
        }

      _ ->
        invalid!(number, "expected seven columns")
    end
  end

  defp inherit_text(value, inherited, number) do
    if trim_ascii(value) == "", do: inherited, else: parse_text!(value, number)
  end

  defp parse_text!(value, number) do
    case trim_ascii(value) do
      "\"\"" -> []
      text -> scan!(text, number, [])
    end
  end

  defp scan!(<<>>, _number, acc), do: Enum.reverse(acc)

  defp scan!(<<"\\u", hex::binary-size(4), rest::binary>>, number, acc) do
    scan!(rest, number, [hex_to_integer!(hex, number) | acc])
  end

  defp scan!(<<"\\x{", rest::binary>>, number, acc) do
    case :binary.match(rest, "}") do
      {position, 1} ->
        hex = binary_part(rest, 0, position)
        tail = binary_part(rest, position + 1, byte_size(rest) - position - 1)
        scan!(tail, number, [hex_to_integer!(hex, number) | acc])

      :nomatch ->
        invalid!(number, "malformed escape")
    end
  end

  defp scan!(<<"\\", _rest::binary>>, number, _acc), do: invalid!(number, "malformed escape")
  defp scan!(<<scalar::utf8, rest::binary>>, number, acc), do: scan!(rest, number, [scalar | acc])
  defp scan!(_text, number, _acc), do: invalid!(number, "invalid UTF-8")

  defp hex_to_integer!(hex, number) do
    case Integer.parse(hex, 16) do
      {value, ""} when byte_size(hex) > 0 and value <= 0x10FFFF -> value
      _ -> invalid!(number, "malformed escape")
    end
  end

  defp parse_status!(value, inherited, number) do
    case trim_ascii(value) do
      "" ->
        inherited

      "[]" ->
        []

      <<"[", body::binary>> ->
        if String.ends_with?(body, "]") do
          body
          |> binary_part(0, byte_size(body) - 1)
          |> String.split(",")
          |> Enum.map(&trim_ascii/1)
          |> Enum.map(fn status ->
            if Regex.match?(~r/^[A-Z][0-9]+(?:_[0-9]+)?$/, status),
              do: status,
              else: invalid!(number, "malformed status")
          end)
        else
          invalid!(number, "malformed status")
        end

      _ ->
        invalid!(number, "malformed status")
    end
  end

  defp trim_ascii(value), do: Regex.replace(~r/^[ \t]+|[ \t]+$/, value, "")

  defp invalid!(number, reason),
    do: raise(ArgumentError, "IDNA fixture line #{number}: #{reason}")
end
