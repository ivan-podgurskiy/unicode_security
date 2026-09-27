defmodule UnicodeSecurity.UnicodeData.IdnaParser do
  @moduledoc false

  @statuses %{
    "valid" => :valid,
    "ignored" => :ignored,
    "mapped" => :mapped,
    "deviation" => :deviation,
    "disallowed" => :disallowed
  }

  @type status :: :valid | :ignored | :mapped | :deviation | :disallowed
  @type idna_record :: {non_neg_integer(), non_neg_integer(), status(), [non_neg_integer()]}

  @spec parse!(binary()) :: [idna_record()]
  def parse!(input) when is_binary(input) do
    {records, next} =
      input
      |> String.split("\n")
      |> Enum.map(fn line -> line |> String.split("#", parts: 2) |> hd() |> String.trim() end)
      |> Enum.reject(&(&1 == ""))
      |> Enum.reduce({[], 0}, fn line, {records, next} ->
        {first, last, status, mapping} = record!(line)

        unless first == next do
          raise ArgumentError, "unsorted, overlapping, or incomplete IDNA ranges"
        end

        {[{first, last, status, mapping} | records], last + 1}
      end)

    unless next == 0x110000 do
      raise ArgumentError, "incomplete IDNA range coverage"
    end

    Enum.reverse(records)
  end

  defp record!(line) do
    fields = line |> String.split(";", trim: false) |> Enum.map(&String.trim/1)

    case fields do
      [range, status] -> record!(range, status, "", "")
      [range, status, mapping] -> record!(range, status, mapping, "")
      [range, status, mapping, marker] -> record!(range, status, mapping, marker)
      _ -> raise ArgumentError, "malformed IDNA record: #{inspect(line)}"
    end
  end

  defp record!(range, token, mapping_text, marker) do
    unless marker in ["", "NV8", "XV8"] do
      raise ArgumentError, "unknown IDNA marker: #{inspect(marker)}"
    end

    status =
      case Map.fetch(@statuses, token) do
        {:ok, known} -> known
        :error -> raise ArgumentError, "unknown IDNA status: #{inspect(token)}"
      end

    mapping = mapping!(mapping_text)

    if (status == :mapped and mapping == []) or
         (status in [:valid, :ignored, :disallowed] and mapping != []) do
      raise ArgumentError, "invalid IDNA mapping for #{status}"
    end

    {first, last} = range!(range)
    {first, last, status, mapping}
  end

  defp mapping!(""), do: []

  defp mapping!(text) do
    text
    |> String.split()
    |> Enum.map(fn scalar ->
      unless Regex.match?(~r/\A[0-9A-F]{4,6}\z/, scalar) do
        raise ArgumentError, "invalid IDNA mapping scalar: #{inspect(scalar)}"
      end

      value = String.to_integer(scalar, 16)

      unless value <= 0x10FFFF and value not in 0xD800..0xDFFF do
        raise ArgumentError, "invalid IDNA mapping scalar: #{inspect(scalar)}"
      end

      value
    end)
  end

  defp range!(text) do
    unless Regex.match?(~r/\A[0-9A-F]{4,6}(?:\.\.[0-9A-F]{4,6})?\z/, text) do
      raise ArgumentError, "invalid IDNA range: #{inspect(text)}"
    end

    values = text |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))
    first = hd(values)
    last = List.last(values)

    unless first <= last and last <= 0x10FFFF do
      raise ArgumentError, "invalid IDNA range: #{inspect(text)}"
    end

    {first, last}
  end
end
