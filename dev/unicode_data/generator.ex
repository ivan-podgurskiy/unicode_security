defmodule UnicodeSecurity.UnicodeData.Generator do
  @moduledoc false

  alias UnicodeSecurity.UnicodeData.Packer
  alias UnicodeSecurity.UnicodeData.Parser
  alias UnicodeSecurity.UnicodeData.ScriptParser
  alias UnicodeSecurity.UnicodeData.Source

  @source_names ["UnicodeData.txt", "DerivedCombiningClass.txt"]
  @output_name "normalization.ex"

  @spec generate_scripts!(Path.t(), Path.t()) :: Path.t()
  def generate_scripts!(source_directory, output_directory) do
    Source.verify!(Source.sources(), source_directory, read_lock!(source_directory))

    aliases =
      source_directory
      |> Path.join("PropertyValueAliases.txt")
      |> File.read!()
      |> ScriptParser.aliases!()

    scripts =
      source_directory
      |> Path.join("Scripts.txt")
      |> File.read!()
      |> ScriptParser.scripts!(aliases)

    extensions =
      source_directory
      |> Path.join("ScriptExtensions.txt")
      |> File.read!()
      |> ScriptParser.extensions!(aliases)

    names = [
      "unknown"
      | aliases |> Map.values() |> Enum.uniq() |> Enum.sort() |> Enum.reject(&(&1 == "unknown"))
    ]

    sets = extensions |> Enum.map(&elem(&1, 2)) |> Enum.uniq() |> Enum.sort()
    script_indices = names |> Enum.with_index() |> Map.new()
    extension_indices = sets |> Enum.with_index(1) |> Map.new()
    packed_scripts = indexed_ranges(scripts, script_indices)
    packed_extensions = indexed_ranges(extensions, extension_indices)

    write_output!(
      output_directory,
      "scripts.ex",
      render_scripts(names, sets, packed_scripts, packed_extensions)
    )
  end

  defp indexed_ranges(records, indices) do
    records
    |> Enum.map(fn {first, last, value} -> {first, last, Map.fetch!(indices, value)} end)
    |> Packer.ranges()
  end

  defp render_scripts(names, sets, scripts, extensions) do
    # Names have been restricted to ASCII letters/underscores by ScriptParser.
    # Emit literal atoms; never intern input-derived atoms in the generator/runtime.
    names_literal = Enum.map_join(names, ",", &(":" <> &1))

    sets_literal =
      Enum.map_join(sets, ",", fn set -> "[" <> Enum.map_join(set, ",", &(":" <> &1)) <> "]" end)

    source = """
    defmodule UnicodeSecurity.Data.Scripts do
      @moduledoc false

      @scripts Base.decode64!(#{encoded_literal(scripts)})
      @extensions Base.decode64!(#{encoded_literal(extensions)})
      @names {#{names_literal}}
      @sets {nil, #{sets_literal}}

      @spec script(non_neg_integer()) :: atom()
      def script(code), do: elem(@names, range(@scripts, code))

      @spec extensions(non_neg_integer()) :: [atom()]
      def extensions(code) do
        case range(@extensions, code) do
          0 -> [script(code)]
          index -> elem(@sets, index)
        end
      end

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

    source |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
  end

  @spec generate_bidi!(Path.t(), Path.t()) :: Path.t()
  def generate_bidi!(source_directory, output_directory) do
    verify_sources!(source_directory, [
      "UnicodeData.txt",
      "DerivedCoreProperties.txt",
      "DerivedBidiClass.txt",
      "BidiBrackets.txt",
      "BidiMirroring.txt"
    ])

    tables =
      for {name, parser, packer} <- [
            {"DerivedBidiClass", &Parser.bidi_classes!/1, &Packer.ranges/1},
            {"DerivedCoreProperties", &Parser.default_ignorables!/1, &Packer.ranges/1},
            {"UnicodeData", &Parser.nonspacing_marks!/1, &Packer.ranges/1},
            {"BidiBrackets", &Parser.bidi_brackets!/1, &Packer.pairs/1},
            {"BidiMirroring", &Parser.bidi_mirroring!/1, &Packer.pairs/1}
          ] do
        source_directory |> Path.join(name <> ".txt") |> File.read!() |> parser.() |> packer.()
      end

    write_output!(output_directory, "bidi.ex", render_bidi(tables))
  end

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
            "#{key}: #{manifest_literal(Map.fetch!(source, key))}"
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

  defp manifest_literal(value) when is_integer(value) do
    Regex.replace(~r/(\d)(?=(\d{3})+$)/, Integer.to_string(value), "\\1_")
  end

  defp manifest_literal(value), do: inspect(value)

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

  defp render_bidi([classes, ignorables, marks, brackets, mirrors]) do
    source = """
    defmodule UnicodeSecurity.Data.Bidi do
      @moduledoc false

      @classes Base.decode64!(#{encoded_literal(classes)})
      @ignorables Base.decode64!(#{encoded_literal(ignorables)})
      @marks Base.decode64!(#{encoded_literal(marks)})
      @brackets Base.decode64!(#{encoded_literal(brackets)})
      @mirrors Base.decode64!(#{encoded_literal(mirrors)})
      @types {:l, :r, :al, :en, :es, :et, :an, :cs, :nsm, :bn, :b, :s, :ws, :on,
              :lre, :lro, :rle, :rlo, :pdf, :lri, :rli, :fsi, :pdi}

      @spec class(non_neg_integer()) :: atom()
      def class(code), do: elem(@types, range(@classes, code))

      @spec default_ignorable?(non_neg_integer()) :: boolean()
      def default_ignorable?(code), do: range(@ignorables, code) == 1

      @spec nonspacing_mark?(non_neg_integer()) :: boolean()
      def nonspacing_mark?(code), do: range(@marks, code) == 1

      @spec bracket(non_neg_integer()) :: {non_neg_integer(), :open | :close} | nil
      def bracket(code) do
        case pair(@brackets, code) do
          nil -> nil
          {target, 1} -> {target, :open}
          {target, 2} -> {target, :close}
        end
      end

      @spec mirror(non_neg_integer()) :: non_neg_integer()
      def mirror(code) do
        case pair(@mirrors, code) do
          nil -> code
          {target, 0} -> target
        end
      end

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

      defp pair(table, code), do: pair(table, code, 0, div(byte_size(table), 9) - 1)
      defp pair(_table, _code, low, high) when low > high, do: nil

      defp pair(table, code, low, high) do
        middle = div(low + high, 2)
        <<matched::32, target::32, kind::8>> = :binary.part(table, middle * 9, 9)

        cond do
          code < matched -> pair(table, code, low, middle - 1)
          code > matched -> pair(table, code, middle + 1, high)
          true -> {target, kind}
        end
      end
    end
    """

    source |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
  end
end
