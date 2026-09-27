defmodule UnicodeSecurity.UnicodeData.IdnaGenerator do
  @moduledoc false

  @status_ids %{valid: 0, ignored: 1, mapped: 2, deviation: 3, disallowed: 4}
  @separators [0x2E, 0x3002, 0xFF0E, 0xFF61]

  @spec render!([tuple()]) :: binary()
  def render!(records) do
    {index, values, _offset, maximum} =
      Enum.reduce(records, {[], [], 0, 1}, fn {first, last, status, mapping},
                                              {index, values, offset, maximum} ->
        count = length(mapping)

        unless offset <= 0xFFFFFFFF and count <= 0xFFFF do
          raise ArgumentError, "IDNA mapping exceeds packed offset or count bounds"
        end

        validate_separators!(first, last, status, mapping)
        status_id = Map.fetch!(@status_ids, status)
        record = <<first::32, last::32, status_id::8, offset::32, count::16>>
        payload = Enum.map(mapping, &<<&1::32>>)
        {[record | index], [payload | values], offset + count, max(maximum, count)}
      end)

    table = index |> Enum.reverse() |> IO.iodata_to_binary()
    mappings = values |> Enum.reverse() |> IO.iodata_to_binary()

    source = """
    defmodule UnicodeSecurity.Data.Idna do
      @moduledoc false

      @table Base.decode64!(#{encoded_literal(table)})
      @mappings Base.decode64!(#{encoded_literal(mappings)})
      @statuses {:valid, :ignored, :mapped, :deviation, :disallowed}

      @type status :: :valid | :ignored | :mapped | :deviation | :disallowed
      @type scalar :: 0..0xD7FF | 0xE000..0x10FFFF

      @spec maximum_mapping_length() :: pos_integer()
      def maximum_mapping_length, do: #{maximum}

      @spec lookup(integer()) :: {status(), [scalar()]}
      def lookup(code) when code < 0 or code > 0x10FFFF or code in 0xD800..0xDFFF,
        do: {:disallowed, []}

      def lookup(code), do: lookup(code, 0, div(byte_size(@table), 15) - 1)

      defp lookup(code, low, high) do
        middle = div(low + high, 2)
        <<first::32, last::32, status_id::8, offset::32, count::16>> =
          :binary.part(@table, middle * 15, 15)

        cond do
          code < first -> lookup(code, low, middle - 1)
          code > last -> lookup(code, middle + 1, high)
          true ->
            payload = :binary.part(@mappings, offset * 4, count * 4)
            values = for <<scalar::32 <- payload>>, do: scalar
            {elem(@statuses, status_id), values}
        end
      end
    end
    """

    source |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
  end

  defp validate_separators!(first, last, :mapped, mapping) do
    if ?. in mapping and
         Enum.any?(first..last, &(&1 not in @separators)) do
      raise ArgumentError, "IDNA mapping introduces an unrecognized label separator"
    end
  end

  # Valid and deviation retain their source scalar in nontransitional processing.
  # Their only possible period is U+002E, which is itself a recognized separator.
  defp validate_separators!(_first, _last, _status, _mapping), do: :ok

  defp encoded_literal(binary) do
    binary |> Base.encode64() |> inspect(limit: :infinity, printable_limit: :infinity)
  end
end
