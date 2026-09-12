defmodule UnicodeSecurity.UnicodeData.Generator do
  @moduledoc false

  alias UnicodeSecurity.UnicodeData.Packer
  alias UnicodeSecurity.UnicodeData.Parser
  alias UnicodeSecurity.UnicodeData.Source

  @source_names ["UnicodeData.txt", "DerivedCombiningClass.txt"]
  @output_name "normalization.ex"

  @spec generate!(Path.t(), Path.t()) :: Path.t()
  def generate!(source_directory, output_directory) do
    verify_sources!(source_directory)

    decompositions =
      source_directory
      |> Path.join("UnicodeData.txt")
      |> File.read!()
      |> Parser.unicode_data!()
      |> Enum.sort_by(&elem(&1, 0))

    combining_classes =
      source_directory
      |> Path.join("DerivedCombiningClass.txt")
      |> File.read!()
      |> Parser.ranges!(:integer)
      |> Enum.reject(fn {_first, _last, value} -> value == 0 end)

    {decomposition_index, decomposition_values} = Packer.mapping(decompositions)
    packed_combining_classes = Packer.ranges(combining_classes)

    contents =
      render(decomposition_index, decomposition_values, packed_combining_classes)

    write_output!(output_directory, @output_name, contents)
  end

  @spec generate_confusables!(Path.t(), Path.t()) :: Path.t()
  def generate_confusables!(source_directory, output_directory) do
    verify_sources!(source_directory, ["confusables.txt"])

    {index, values} =
      source_directory
      |> Path.join("confusables.txt")
      |> File.read!()
      |> Parser.confusables!()
      |> Enum.sort_by(&elem(&1, 0))
      |> Packer.mapping()

    write_output!(output_directory, "confusables.ex", render_confusables(index, values))
  end

  @spec generate_manifest!(Path.t(), Path.t()) :: Path.t()
  def generate_manifest!(source_directory, output_directory) do
    lock = read_lock!(source_directory)
    declarations = Source.sources()
    Source.verify!(declarations, source_directory, lock)

    sources =
      declarations
      |> Enum.sort_by(& &1.name)
      |> Enum.map(fn declaration ->
        declaration
        |> Map.take([:name, :url, :version, :status])
        |> Map.merge(Map.take(Map.fetch!(lock, declaration.name), [:bytes, :sha256]))
      end)

    release_status = if Enum.all?(sources, &(&1.status == :final)), do: :final, else: :draft

    source_literals =
      Enum.map_join(sources, ",\n", fn source ->
        fields =
          Enum.map_join([:name, :url, :version, :bytes, :sha256, :status], ",\n", fn key ->
            "#{key}: #{inspect(Map.fetch!(source, key))}"
          end)

        "%{#{fields}}"
      end)

    contents = """
    defmodule UnicodeSecurity.Data.Manifest do
      @moduledoc false

      @spec get() :: map()
      def get, do: %{release_status: #{inspect(release_status)}, sources: [#{source_literals}]}
    end
    """

    contents = contents |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
    write_output!(output_directory, "manifest.ex", contents)
  end

  defp write_output!(output_directory, output_name, contents) do
    output_path = Path.join(output_directory, output_name)
    temporary_path = output_path <> ".tmp"

    File.mkdir_p!(output_directory)

    try do
      File.write!(temporary_path, contents, [:binary])
      File.rename!(temporary_path, output_path)
    after
      if File.exists?(temporary_path), do: File.rm!(temporary_path)
    end

    output_path
  end

  defp verify_sources!(source_directory, source_names \\ @source_names) do
    lock = read_lock!(source_directory)
    declarations = Enum.filter(Source.sources(), &(&1.name in source_names))
    relevant_lock = Map.take(lock, source_names)
    Source.verify!(declarations, source_directory, relevant_lock)
  end

  defp read_lock!(source_directory) do
    lock_path = Path.join(Path.dirname(source_directory), "sources.lock")
    {lock, _binding} = Code.eval_file(lock_path)

    unless is_map(lock) do
      raise ArgumentError, "Unicode source lock must evaluate to a map"
    end

    lock
  end

  defp render(decomposition_index, decomposition_values, combining_classes) do
    source = """
    defmodule UnicodeSecurity.Data.Normalization do
      @moduledoc false

      @record_size 10
      @decomposition_index Base.decode64!(#{encoded_literal(decomposition_index)})
      @decomposition_values Base.decode64!(#{encoded_literal(decomposition_values)})
      @combining_classes Base.decode64!(#{encoded_literal(combining_classes)})

      @spec decomposition(non_neg_integer()) :: [non_neg_integer()] | nil
      def decomposition(codepoint),
        do: lookup_mapping(@decomposition_index, @decomposition_values, codepoint)

      @spec combining_class(non_neg_integer()) :: 0..255
      def combining_class(codepoint), do: lookup_range(@combining_classes, codepoint, 0)

      defp lookup_mapping(index, values, codepoint) do
        lookup_mapping(index, values, codepoint, 0, div(byte_size(index), @record_size) - 1)
      end

      defp lookup_mapping(_index, _values, _codepoint, low, high) when low > high, do: nil

      defp lookup_mapping(index, values, codepoint, low, high) do
        middle = div(low + high, 2)

        <<matched::32, offset::32, count::16>> =
          :binary.part(index, middle * @record_size, @record_size)

        cond do
          codepoint < matched -> lookup_mapping(index, values, codepoint, low, middle - 1)
          codepoint > matched -> lookup_mapping(index, values, codepoint, middle + 1, high)
          true -> unpack_values(values, offset, count)
        end
      end

      defp unpack_values(values, offset, count) do
        for <<value::32 <- :binary.part(values, offset * 4, count * 4)>>, do: value
      end

      defp lookup_range(ranges, codepoint, default) do
        lookup_range(ranges, codepoint, default, 0, div(byte_size(ranges), @record_size) - 1)
      end

      defp lookup_range(_ranges, _codepoint, default, low, high) when low > high, do: default

      defp lookup_range(ranges, codepoint, default, low, high) do
        middle = div(low + high, 2)
        <<first::32, last::32, value::16>> =
          :binary.part(ranges, middle * @record_size, @record_size)

        cond do
          codepoint < first -> lookup_range(ranges, codepoint, default, low, middle - 1)
          codepoint > last -> lookup_range(ranges, codepoint, default, middle + 1, high)
          true -> value
        end
      end
    end
    """

    source
    |> Code.format_string!()
    |> IO.iodata_to_binary()
    |> Kernel.<>("\n")
  end

  defp render_confusables(index, values) do
    source = """
    defmodule UnicodeSecurity.Data.Confusables do
      @moduledoc false

      @record_size 10
      @index Base.decode64!(#{encoded_literal(index)})
      @values Base.decode64!(#{encoded_literal(values)})

      @spec mapping(non_neg_integer()) :: [non_neg_integer()] | nil
      def mapping(codepoint), do: lookup_mapping(@index, @values, codepoint)

      defp lookup_mapping(index, values, codepoint) do
        lookup_mapping(index, values, codepoint, 0, div(byte_size(index), @record_size) - 1)
      end

      defp lookup_mapping(_index, _values, _codepoint, low, high) when low > high, do: nil

      defp lookup_mapping(index, values, codepoint, low, high) do
        middle = div(low + high, 2)

        <<matched::32, offset::32, count::16>> =
          :binary.part(index, middle * @record_size, @record_size)

        cond do
          codepoint < matched -> lookup_mapping(index, values, codepoint, low, middle - 1)
          codepoint > matched -> lookup_mapping(index, values, codepoint, middle + 1, high)
          true -> unpack_values(values, offset, count)
        end
      end

      defp unpack_values(values, offset, count) do
        for <<value::32 <- :binary.part(values, offset * 4, count * 4)>>, do: value
      end
    end
    """

    source
    |> Code.format_string!()
    |> IO.iodata_to_binary()
    |> Kernel.<>("\n")
  end

  defp encoded_literal(binary) do
    binary
    |> Base.encode64()
    |> inspect(limit: :infinity, printable_limit: :infinity)
  end
end
