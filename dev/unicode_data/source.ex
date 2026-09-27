defmodule UnicodeSecurity.UnicodeData.Source do
  @moduledoc false

  @unicode_version "18.0.0"

  @sources [
    %{
      name: "DerivedNormalizationProps.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/DerivedNormalizationProps.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "PropList.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/PropList.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "DerivedJoiningType.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedJoiningType.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "IndicSyllabicCategory.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/IndicSyllabicCategory.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "IdentifierStatus.txt",
      url: "https://www.unicode.org/Public/draft/security/IdentifierStatus.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "IdentifierType.txt",
      url: "https://www.unicode.org/Public/draft/security/IdentifierType.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "Scripts.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/Scripts.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "ScriptExtensions.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/ScriptExtensions.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "PropertyValueAliases.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/PropertyValueAliases.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "UnicodeData.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "DerivedCombiningClass.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedCombiningClass.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "NormalizationTest.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/NormalizationTest.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "confusables.txt",
      url: "https://www.unicode.org/Public/draft/security/confusables.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "DerivedCoreProperties.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/DerivedCoreProperties.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "DerivedBidiClass.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedBidiClass.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "BidiBrackets.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/BidiBrackets.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "BidiMirroring.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/BidiMirroring.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "BidiTest.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/BidiTest.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "BidiCharacterTest.txt",
      url: "https://www.unicode.org/Public/18.0.0/ucd/BidiCharacterTest.txt",
      version: "18.0.0",
      status: :draft
    },
    %{
      name: "IdnaMappingTable.txt",
      url: "https://www.unicode.org/Public/18.0.0/idna/IdnaMappingTable.txt",
      version: "18.0.0",
      status: :final
    },
    %{
      name: "IdnaTestV2.txt",
      url: "https://www.unicode.org/Public/18.0.0/idna/IdnaTestV2.txt",
      version: "18.0.0",
      status: :final
    }
  ]

  @spec sources() :: [map()]
  def sources, do: @sources

  @spec fetch!([map()], Path.t(), :locked | :update_lock) :: map()
  def fetch!(declarations, directory, mode \\ :locked) when mode in [:locked, :update_lock] do
    declarations = validate_fetch_declarations!(declarations)
    parent = Path.dirname(directory)
    lock_path = Path.join(parent, "sources.lock")

    expected_lock =
      if mode == :locked and File.regular?(lock_path) do
        {lock, _binding} = Code.eval_file(lock_path)

        unless is_map(lock) do
          raise ArgumentError, "Unicode source lock must evaluate to a map"
        end

        lock
      end

    staging = temporary_path(directory, "staging")

    File.mkdir_p!(parent)
    File.mkdir!(staging)

    try do
      Enum.each(declarations, &fetch_source!(&1, staging))
      if expected_lock, do: verify!(declarations, staging, expected_lock)
      lock = lock!(declarations, staging)
      install_staged!(staging, directory)
      lock
    after
      if File.exists?(staging), do: File.rm_rf!(staging)
    end
  end

  @spec lock!([map()], Path.t()) :: %{
          String.t() => %{bytes: non_neg_integer(), sha256: String.t()}
        }
  def lock!(declarations, directory) do
    declarations
    |> validate_declarations!()
    |> Map.new(fn %{name: name} -> {name, metadata!(Path.join(directory, name))} end)
  end

  @spec verify!([map()], Path.t(), map()) :: :ok
  def verify!(declarations, directory, lock) when is_map(lock) do
    declarations = validate_declarations!(declarations)
    declared_names = declarations |> Enum.map(& &1.name) |> MapSet.new()
    locked_names = lock |> Map.keys() |> MapSet.new()

    if declared_names != locked_names do
      raise ArgumentError, "lock entries do not match source declarations"
    end

    Enum.each(declarations, fn %{name: name} ->
      actual = metadata!(Path.join(directory, name))
      expected = Map.fetch!(lock, name)

      if actual.bytes != expected.bytes do
        raise ArgumentError, "byte-size mismatch for #{name}"
      end

      if actual.sha256 != expected.sha256 do
        raise ArgumentError, "SHA-256 mismatch for #{name}"
      end
    end)

    :ok
  end

  @doc false
  @spec install_staged!(Path.t(), Path.t(), (Path.t() -> term())) :: :ok
  def install_staged!(staging, directory, cleanup \\ &File.rm_rf!/1) do
    if File.exists?(directory) do
      backup = temporary_path(directory, "backup")
      File.rename!(directory, backup)

      try do
        File.rename!(staging, directory)
      rescue
        error ->
          if File.exists?(directory), do: File.rm_rf!(directory)
          File.rename!(backup, directory)
          reraise error, __STACKTRACE__
      end

      cleanup.(backup)
      :ok
    else
      File.rename!(staging, directory)
    end
  end

  defp validate_declarations!(declarations) when is_list(declarations) do
    Enum.each(declarations, fn declaration ->
      unless declaration.version == @unicode_version do
        raise ArgumentError, "unsupported Unicode version: #{inspect(declaration.version)}"
      end

      unless declaration.status in [:draft, :final] do
        raise ArgumentError, "unsupported Unicode source status"
      end

      unless is_binary(declaration.name) and Path.basename(declaration.name) == declaration.name do
        raise ArgumentError, "invalid Unicode source name: #{inspect(declaration.name)}"
      end
    end)

    names = Enum.map(declarations, & &1.name)

    if length(names) != MapSet.size(MapSet.new(names)) do
      raise ArgumentError, "duplicate Unicode source names"
    end

    declarations
  end

  defp validate_fetch_declarations!(declarations) do
    declarations = validate_declarations!(declarations)

    Enum.each(declarations, fn declaration ->
      unless is_binary(declaration.url) do
        raise ArgumentError, "invalid URL for #{declaration.name}"
      end
    end)

    declarations
  end

  defp fetch_source!(source, staging) do
    request = {String.to_charlist(source.url), []}
    request_options = [body_format: :binary]

    case :httpc.request(:get, request, http_options(source.url), request_options) do
      {:ok, {{_http_version, 200, _reason}, _headers, bytes}} ->
        verify_download_version!(source, bytes)
        File.write!(Path.join(staging, source.name), bytes, [:binary, :exclusive])

      {:ok, {{_http_version, status, reason}, _headers, _bytes}} ->
        raise "HTTP #{status} #{reason} fetching #{source.url}"

      {:error, reason} ->
        raise "failed to fetch #{source.url}: #{inspect(reason)}"
    end
  end

  defp http_options("https://" <> _rest) do
    hostname_match = :public_key.pkix_verify_hostname_match_fun(:https)

    [
      autoredirect: true,
      connect_timeout: 30_000,
      timeout: 120_000,
      ssl: [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        depth: 4,
        customize_hostname_check: [match_fun: hostname_match]
      ]
    ]
  end

  defp http_options(_url) do
    [autoredirect: true, connect_timeout: 5_000, timeout: 5_000]
  end

  defp verify_download_version!(%{name: "UnicodeData.txt"} = source, bytes) do
    version_path = "/#{source.version}/"

    unless String.contains?(source.url, version_path) and valid_unicode_data?(bytes) do
      raise "invalid UnicodeData records or version evidence for #{source.name}"
    end
  end

  defp verify_download_version!(source, bytes) do
    header = binary_part(bytes, 0, min(byte_size(bytes), 8_192))

    unless String.contains?(header, source.version) do
      raise "version validation failed for #{source.name}"
    end
  end

  defp valid_unicode_data?(bytes) do
    records =
      bytes
      |> String.split("\n", trim: false)
      |> Enum.map(&String.trim_trailing(&1, "\r"))
      |> drop_final_empty_record()

    records != [] and
      records
      |> Enum.map(&String.split(&1, ";", trim: false))
      |> valid_unicode_data_records?()
  end

  defp drop_final_empty_record(records) do
    case Enum.reverse(records) do
      ["" | reversed_records] -> Enum.reverse(reversed_records)
      _records_without_final_newline -> records
    end
  end

  defp valid_unicode_data_records?([]), do: true

  defp valid_unicode_data_records?([record | remaining]) do
    if surrogate_first_record?(record) do
      case remaining do
        [last_record | rest] ->
          valid_surrogate_pair?(record, last_record) and valid_unicode_data_records?(rest)

        [] ->
          false
      end
    else
      valid_unicode_data_record?(record) and valid_unicode_data_records?(remaining)
    end
  end

  defp valid_unicode_data_record?(record) do
    case record do
      [code | _fields] ->
        unicode_scalar?(code) and valid_unicode_data_mappings?(record)
    end
  end

  defp surrogate_first_record?([code, name, "Cs" | _rest] = record) do
    length(record) == 15 and surrogate_code_point?(code) and
      String.starts_with?(name, "<") and String.ends_with?(name, ", First>")
  end

  defp surrogate_first_record?(_record), do: false

  defp valid_surrogate_pair?(
         [first_code, first_name, "Cs" | first_properties] = first,
         [last_code, last_name, "Cs" | last_properties] = last
       ) do
    length(first) == 15 and length(last) == 15 and surrogate_code_point?(first_code) and
      surrogate_code_point?(last_code) and code_point!(first_code) <= code_point!(last_code) and
      sentinel_names_match?(first_name, last_name) and
      first_properties == last_properties and valid_unicode_data_mappings?(first)
  end

  defp valid_surrogate_pair?(_first, _last), do: false

  defp sentinel_names_match?(first, last) do
    String.starts_with?(last, "<") and String.ends_with?(last, ", Last>") and
      String.replace_suffix(first, "First>", "") == String.replace_suffix(last, "Last>", "")
  end

  defp valid_unicode_data_mappings?([
         _code,
         _name,
         _category,
         _combining_class,
         _bidi_class,
         decomposition,
         _decimal,
         _digit,
         _numeric,
         _mirrored,
         _unicode_1_name,
         _iso_comment,
         simple_uppercase,
         simple_lowercase,
         simple_titlecase
       ]) do
    valid_decomposition?(decomposition) and
      Enum.all?([simple_uppercase, simple_lowercase, simple_titlecase], fn mapping ->
        mapping == "" or unicode_scalar?(mapping)
      end)
  end

  defp valid_unicode_data_mappings?(_malformed_record), do: false

  defp valid_decomposition?(""), do: true

  defp valid_decomposition?(decomposition) do
    code_points =
      decomposition
      |> String.split(" ", trim: true)
      |> Enum.reject(&(String.starts_with?(&1, "<") and String.ends_with?(&1, ">")))

    code_points != [] and Enum.all?(code_points, &unicode_scalar?/1)
  end

  defp unicode_scalar?(hexadecimal) do
    case parse_code_point(hexadecimal) do
      {:ok, code_point} -> code_point not in 0xD800..0xDFFF
      :error -> false
    end
  end

  defp surrogate_code_point?(hexadecimal) do
    case parse_code_point(hexadecimal) do
      {:ok, code_point} -> code_point in 0xD800..0xDFFF
      :error -> false
    end
  end

  defp code_point!(hexadecimal) do
    {:ok, code_point} = parse_code_point(hexadecimal)
    code_point
  end

  defp parse_code_point(hexadecimal) do
    case Integer.parse(hexadecimal, 16) do
      {code_point, ""} when code_point in 0..0x10FFFF -> {:ok, code_point}
      _invalid_hexadecimal -> :error
    end
  end

  defp temporary_path(directory, purpose) do
    suffix = System.unique_integer([:positive, :monotonic])
    "#{directory}.#{purpose}-#{suffix}"
  end

  defp metadata!(path) do
    bytes = File.read!(path)

    %{
      bytes: byte_size(bytes),
      sha256: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
    }
  end
end
