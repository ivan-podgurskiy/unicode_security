defmodule UnicodeSecurity.UnicodeData.ScriptParser do
  @moduledoc false

  @type property_record(value) :: {non_neg_integer(), non_neg_integer(), value}

  @spec aliases!(binary()) :: %{binary() => binary()}
  def aliases!(input) do
    header!(input, "PropertyValueAliases")

    input
    |> lines()
    |> Enum.reduce(%{}, fn line, aliases ->
      case fields(line) do
        ["sc", short, long | other] -> alias_record!([short, long | other], long, aliases)
        ["sc" | _] -> raise ArgumentError, "malformed script alias record: #{inspect(line)}"
        _ -> aliases
      end
    end)
  end

  @spec scripts!(binary(), map()) :: [property_record(binary())]
  def scripts!(input, aliases) do
    property!(input, "Scripts", "Unknown", &alias!(&1, aliases))
  end

  @spec extensions!(binary(), map()) :: [property_record([binary()])]
  def extensions!(input, aliases) do
    property!(input, "ScriptExtensions", "<script>", &extension!(&1, aliases))
  end

  defp alias_record!(names, long, aliases) do
    unless Enum.all?(names, &Regex.match?(~r/\A[A-Za-z][A-Za-z_]*\z/, &1)) do
      raise ArgumentError, "invalid script alias: #{inspect(names)}"
    end

    Enum.reduce(Enum.uniq(names), aliases, fn name, acc ->
      if Map.has_key?(acc, name), do: raise(ArgumentError, "duplicate script alias: #{name}")
      Map.put(acc, name, String.downcase(long))
    end)
  end

  defp property!(input, name, default, value_parser) do
    header!(input, name)

    defaults =
      input
      |> String.split("\n")
      |> Enum.filter(&String.contains?(&1, "@missing:"))
      |> Enum.map(&String.trim/1)

    unless defaults == ["# @missing: 0000..10FFFF; #{default}"] do
      raise ArgumentError, "invalid #{name} default declaration"
    end

    input
    |> lines()
    |> Enum.map(&record!(&1, value_parser))
    |> Enum.sort()
    |> ordered!()
  end

  defp record!(line, value_parser) do
    case fields(line) do
      [range, value] ->
        {first, last} = range!(range)
        {first, last, value_parser.(value)}

      _ ->
        raise ArgumentError, "malformed script property record: #{inspect(line)}"
    end
  end

  defp range!(range) do
    unless Regex.match?(~r/\A[0-9A-F]{4,6}(?:\.\.[0-9A-F]{4,6})?\z/, range) do
      raise ArgumentError, "invalid script range: #{range}"
    end

    points = range |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))
    first = hd(points)
    last = List.last(points)

    unless first <= last and last <= 0x10FFFF and (last < 0xD800 or first > 0xDFFF) do
      raise ArgumentError, "invalid script scalar range: #{range}"
    end

    {first, last}
  end

  defp ordered!(records) do
    _last =
      Enum.reduce(records, -1, fn {first, last, _}, previous ->
        if first <= previous, do: raise(ArgumentError, "overlapping script property ranges")
        last
      end)

    records
  end

  defp alias!(name, aliases) do
    case Map.fetch(aliases, name) do
      {:ok, value} -> value
      :error -> raise ArgumentError, "unknown script alias: #{inspect(name)}"
    end
  end

  defp extension!(value, aliases) do
    values = value |> String.split() |> Enum.map(&alias!(&1, aliases))

    unless values != [] and length(values) == length(Enum.uniq(values)) and
             Enum.all?(values, &(&1 not in ["common", "inherited", "unknown"])) do
      raise ArgumentError, "invalid explicit Script_Extensions set: #{inspect(value)}"
    end

    Enum.sort(values)
  end

  defp header!(input, name) do
    unless input |> String.split("\n", parts: 2) |> hd() |> String.trim() ==
             "# #{name}-18.0.0.txt" do
      raise ArgumentError, "missing #{name} Unicode 18.0.0 header"
    end
  end

  defp fields(line), do: line |> String.split(";") |> Enum.map(&String.trim/1)

  defp lines(input) do
    input
    |> String.split("\n")
    |> Enum.map(fn line -> line |> String.split("#", parts: 2) |> hd() |> String.trim() end)
    |> Enum.reject(&(&1 == ""))
  end
end
