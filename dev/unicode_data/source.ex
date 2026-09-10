defmodule UnicodeSecurity.UnicodeData.Source do
  @moduledoc false

  @unicode_version "18.0.0"

  @sources [
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
    }
  ]

  @spec sources() :: [map()]
  def sources, do: @sources

  @spec fetch!([map()], Path.t()) :: map()
  def fetch!(declarations, directory) do
    declarations = validate_fetch_declarations!(declarations)
    parent = Path.dirname(directory)
    staging = temporary_path(directory, "staging")

    File.mkdir_p!(parent)
    File.mkdir!(staging)

    try do
      Enum.each(declarations, &fetch_source!(&1, staging))
      lock = lock!(declarations, staging)
      replace_directory!(staging, directory)
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

  defp validate_declarations!(declarations) when is_list(declarations) do
    Enum.each(declarations, fn declaration ->
      unless declaration.version == @unicode_version do
        raise ArgumentError, "unsupported Unicode version: #{inspect(declaration.version)}"
      end

      unless declaration.status == :draft do
        raise ArgumentError, "unsupported Unicode source status: #{inspect(declaration.status)}"
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
    hostname_match = apply(:public_key, :pkix_verify_hostname_match_fun, [:https])

    [
      autoredirect: true,
      connect_timeout: 30_000,
      timeout: 120_000,
      ssl: [
        verify: :verify_peer,
        cacerts: apply(:public_key, :cacerts_get, []),
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

    unless String.contains?(source.url, version_path) and String.contains?(bytes, ";") do
      raise "version validation failed for #{source.name}"
    end
  end

  defp verify_download_version!(source, bytes) do
    header = binary_part(bytes, 0, min(byte_size(bytes), 8_192))

    unless String.contains?(header, source.version) do
      raise "version validation failed for #{source.name}"
    end
  end

  defp replace_directory!(staging, directory) do
    if File.exists?(directory) do
      backup = temporary_path(directory, "backup")
      File.rename!(directory, backup)

      try do
        File.rename!(staging, directory)
        File.rm_rf!(backup)
      rescue
        error ->
          if File.exists?(directory), do: File.rm_rf!(directory)
          File.rename!(backup, directory)
          reraise error, __STACKTRACE__
      end
    else
      File.rename!(staging, directory)
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
