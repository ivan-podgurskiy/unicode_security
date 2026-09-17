defmodule UnicodeSecurity.UnicodeData.ProfileGenerator do
  @moduledoc false

  alias UnicodeSecurity.UnicodeData.Packer

  @categories [
    :cn,
    :lu,
    :ll,
    :lt,
    :lm,
    :lo,
    :mn,
    :mc,
    :me,
    :nd,
    :nl,
    :no,
    :pc,
    :pd,
    :ps,
    :pe,
    :pi,
    :pf,
    :po,
    :sm,
    :sc,
    :sk,
    :so,
    :zs,
    :zl,
    :zp,
    :cc,
    :cf,
    :cs,
    :co
  ]
  @joining [:u, :r, :l, :d, :c, :t]

  @spec composition_pairs!(map(), [tuple()]) :: [tuple()]
  def composition_pairs!(decompositions, exclusions) do
    excluded = MapSet.new(for {first, last, _} <- exclusions, code <- first..last, do: code)

    pairs =
      decompositions
      |> Enum.flat_map(fn
        {code, [first, second]} ->
          if MapSet.member?(excluded, code), do: [], else: [{first, second, code}]

        _mapping ->
          []
      end)
      |> Enum.sort()

    if length(pairs) != MapSet.size(MapSet.new(pairs, fn {a, b, _} -> {a, b} end)),
      do: raise(ArgumentError, "duplicate canonical composition pair")

    pairs
  end

  @spec render_profile!([tuple()], map(), [tuple()], [tuple()]) :: binary()
  def render_profile!(categories, properties, joining, vowels) do
    source = """
    defmodule UnicodeSecurity.Data.Profile do
      @moduledoc false

      @categories Base.decode64!(#{encoded(index(categories, @categories))})
      @white_space Base.decode64!(#{encoded(Packer.ranges(properties.white_space))})
      @bidi_control Base.decode64!(#{encoded(Packer.ranges(properties.bidi_control))})
      @joining Base.decode64!(#{encoded(index(joining, @joining))})
      @vowels Base.decode64!(#{encoded(Packer.ranges(vowels))})
      @category_values #{inspect(List.to_tuple(@categories))}
      @joining_values #{inspect(List.to_tuple(@joining))}

      @spec category(non_neg_integer()) :: atom()
      def category(code), do: elem(@category_values, range(@categories, code))
      @spec white_space?(non_neg_integer()) :: boolean()
      def white_space?(code), do: range(@white_space, code) == 1
      @spec bidi_control?(non_neg_integer()) :: boolean()
      def bidi_control?(code), do: range(@bidi_control, code) == 1
      @spec joining_type(non_neg_integer()) :: :u | :r | :l | :d | :c | :t
      def joining_type(code), do: elem(@joining_values, range(@joining, code))
      @spec vowel_dependent?(non_neg_integer()) :: boolean()
      def vowel_dependent?(code), do: range(@vowels, code) == 1

      defp range(table, code), do: range(table, code, 0, div(byte_size(table), 10) - 1)
      defp range(_table, _code, low, high) when low > high, do: 0
      defp range(table, code, low, high) do
        middle = div(low + high, 2)
        <<first::32, last::32, value::16>> = :binary.part(table, middle * 10, 10)
        cond do
          code < first -> range(table, code, low, middle - 1)
          code > last -> range(table, code, middle + 1, high)
          true -> value
        end
      end
    end
    """

    format(source)
  end

  @spec render_composition!([tuple()]) :: binary()
  def render_composition!(pairs) do
    packed =
      pairs
      |> Enum.map(fn {a, b, code} -> <<a::32, b::32, code::32>> end)
      |> IO.iodata_to_binary()

    source = """
    defmodule UnicodeSecurity.Data.Composition do
      @moduledoc false

      @pairs Base.decode64!(#{encoded(packed)})
      @spec compose(non_neg_integer(), non_neg_integer()) :: non_neg_integer() | nil
      def compose(first, second), do: pair({first, second}, 0, div(byte_size(@pairs), 12) - 1)
      defp pair(_key, low, high) when low > high, do: nil
      defp pair(key, low, high) do
        middle = div(low + high, 2)
        <<first::32, second::32, code::32>> = :binary.part(@pairs, middle * 12, 12)
        cond do
          key < {first, second} -> pair(key, low, middle - 1)
          key > {first, second} -> pair(key, middle + 1, high)
          true -> code
        end
      end
    end
    """

    format(source)
  end

  defp index(records, values) do
    indices = values |> Enum.with_index() |> Map.new()

    records
    |> Enum.map(fn {first, last, value} -> {first, last, Map.fetch!(indices, value)} end)
    |> Packer.ranges()
  end

  defp encoded(bytes),
    do: bytes |> Base.encode64() |> inspect(limit: :infinity, printable_limit: :infinity)

  defp format(source),
    do: source |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
end
