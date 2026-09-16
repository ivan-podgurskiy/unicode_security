defmodule UnicodeSecurity.UnicodeData.IdentifierParser do
  @moduledoc false

  @type property_record(value) :: {non_neg_integer(), non_neg_integer(), value}

  @spec statuses!(binary()) :: [property_record(:allowed | :restricted)]
  def statuses!(input) do
    property!(input, "IdentifierStatus", "Restricted", &status!/1)
  end

  @spec types!(binary()) :: [property_record([atom()])]
  def types!(input) do
    property!(input, "IdentifierType", "Not_Character", &types_value!/1)
  end

  defp property!(input, name, default, value_parser) do
    header!(input, name)
    default!(input, name, default)

    input
    |> lines()
    |> Enum.map(&record!(&1, value_parser))
    |> Enum.sort()
    |> ordered!()
  end

  defp header!(input, name) do
    lines = String.split(input, "\n")

    versions =
      lines |> Enum.map(&String.trim/1) |> Enum.filter(&String.starts_with?(&1, "# Version:"))

    unless lines |> hd() |> String.trim() == "# #{name}.txt" and
             versions == ["# Version: 18.0.0"] do
      raise ArgumentError, "missing #{name} Unicode 18.0.0 header"
    end
  end

  defp default!(input, name, default) do
    defaults =
      input
      |> String.split("\n")
      |> Enum.filter(&String.contains?(&1, "@missing:"))
      |> Enum.map(&String.trim/1)

    unless defaults == ["# @missing: 0000..10FFFF; #{default}"] do
      raise ArgumentError, "invalid #{name} default declaration"
    end
  end

  defp record!(line, value_parser) do
    case fields(line) do
      [range, value] ->
        {first, last} = range!(range)
        {first, last, value_parser.(value)}

      _ ->
        raise ArgumentError, "malformed identifier property record: #{inspect(line)}"
    end
  end

  defp status!("Allowed"), do: :allowed
  defp status!("Restricted"), do: :restricted

  defp status!(value),
    do: raise(ArgumentError, "unknown Identifier_Status value: #{inspect(value)}")

  defp types_value!(value) do
    types = value |> String.split() |> Enum.map(&type!/1)

    unless types != [] and length(types) == length(Enum.uniq(types)) do
      raise ArgumentError, "invalid Identifier_Type set: #{inspect(value)}"
    end

    Enum.sort(types)
  end

  defp type!("Not_Character"), do: :not_character
  defp type!("Deprecated"), do: :deprecated
  defp type!("Default_Ignorable"), do: :default_ignorable
  defp type!("Not_NFKC"), do: :not_nfkc
  defp type!("Not_XID"), do: :not_xid
  defp type!("Exclusion"), do: :exclusion
  defp type!("Obsolete"), do: :obsolete
  defp type!("Technical"), do: :technical
  defp type!("Uncommon_Use"), do: :uncommon_use
  defp type!("Limited_Use"), do: :limited_use
  defp type!("Inclusion"), do: :inclusion
  defp type!("Recommended"), do: :recommended
  defp type!(value), do: raise(ArgumentError, "unknown Identifier_Type value: #{inspect(value)}")

  defp range!(range) do
    unless Regex.match?(~r/\A[0-9A-F]{4,6}(?:\.\.[0-9A-F]{4,6})?\z/, range) do
      raise ArgumentError, "invalid identifier range: #{range}"
    end

    points = range |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))
    first = hd(points)
    last = List.last(points)

    unless first <= last and last <= 0x10FFFF and (last < 0xD800 or first > 0xDFFF) do
      raise ArgumentError, "invalid identifier scalar range: #{range}"
    end

    {first, last}
  end

  defp ordered!(records) do
    _last =
      Enum.reduce(records, -1, fn {first, last, _value}, previous ->
        if first <= previous do
          raise ArgumentError, "overlapping identifier property ranges"
        end

        last
      end)

    records
  end

  defp fields(line), do: line |> String.split(";") |> Enum.map(&String.trim/1)

  defp lines(input) do
    input
    |> String.split("\n")
    |> Enum.map(fn line -> line |> String.split("#", parts: 2) |> hd() |> String.trim() end)
    |> Enum.reject(&(&1 == ""))
  end
end
