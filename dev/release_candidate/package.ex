defmodule UnicodeSecurity.ReleaseCandidate.Package do
  @moduledoc false

  alias UnicodeSecurity.ReleaseCandidate.Command

  @root_files ~w(.formatter.exs CHANGELOG.md LICENSE README.md THIRD_PARTY_NOTICES.md hex_metadata.config mix.exs)
  @archive_limit 1_048_576
  @unpacked_limit 4_194_304

  @spec verify(binary(), keyword()) :: {:ok, map()} | {:error, map()}
  def verify(root, opts \\ []) do
    temporary =
      Path.join(
        Keyword.get(opts, :tmp_dir, System.tmp_dir!()),
        "unicode-security-verification-#{Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)}"
      )

    try do
      File.mkdir_p!(temporary)
      env = private_environment(temporary)
      copy_hex_archive(temporary)
      command_opts = Keyword.put(opts, :env, env)
      archive = Path.join(temporary, "package.tar")
      unpacked = Path.join(temporary, "package")
      consumer = Path.join(temporary, "consumer")

      with {:ok, _} <- Command.run(root, "mix", ["hex.build", "--output", archive], command_opts),
           {:ok, _} <-
             Command.run(
               root,
               "mix",
               ["hex.build", "--unpack", "--output", unpacked],
               command_opts
             ),
           {:ok, metadata} <- validate_payload(root, archive, unpacked),
           :ok <- write_consumer(consumer, unpacked),
           {:ok, _} <- Command.run(consumer, "mix", ["deps.get", "--only", "prod"], command_opts),
           {:ok, _} <-
             Command.run(consumer, "mix", ["compile", "--warnings-as-errors"], command_opts),
           {:ok, _} <-
             Command.run(consumer, "mix", ["run", "--no-compile", "consumer.exs"], command_opts) do
        {:ok, Map.put(metadata, :consumer, :passed)}
      end
    rescue
      exception ->
        {:error,
         %{reason: :exception, output: Exception.format(:error, exception, __STACKTRACE__)}}
    after
      File.rm_rf!(temporary)
    end
  end

  @spec expected_files(binary()) :: [binary()]
  def expected_files(root) do
    case Command.run(root, "git", ["ls-files", "-z", "--", "lib"]) do
      {:ok, %{output: output}} ->
        runtime =
          output
          |> String.split(<<0>>, trim: true)
          |> Enum.map(&normalize/1)
          |> Enum.filter(&(String.starts_with?(&1, "lib/") and String.ends_with?(&1, ".ex")))

        Enum.sort(@root_files ++ runtime)

      {:error, result} ->
        raise "Cannot enumerate tracked package files: #{inspect(result)}"
    end
  end

  @spec validate_payload(binary(), binary(), binary()) :: {:ok, map()} | {:error, map()}
  def validate_payload(root, archive, unpacked) do
    entries = unpacked_files(unpacked)
    files = entries |> Enum.map(fn {path, _} -> normalize(path) end) |> Enum.sort()
    expected = expected_files(root)
    unexpected = files -- expected
    missing = expected -- files
    bytes = File.stat!(archive).size
    unpacked_bytes = Enum.reduce(entries, 0, fn {_, path}, sum -> sum + File.stat!(path).size end)

    cond do
      unexpected != [] or missing != [] ->
        {:error, %{reason: :payload_files, unexpected: unexpected, missing: missing}}

      bytes > @archive_limit ->
        {:error, %{reason: :archive_size, bytes: bytes, limit: @archive_limit}}

      unpacked_bytes > @unpacked_limit ->
        {:error,
         %{reason: :unpacked_size, unpacked_bytes: unpacked_bytes, limit: @unpacked_limit}}

      true ->
        digest =
          archive
          |> File.read!()
          |> then(&:crypto.hash(:sha256, &1))
          |> Base.encode16(case: :lower)

        {:ok, %{archive: archive, bytes: bytes, sha256: digest, files: files}}
    end
  end

  defp unpacked_files(root, relative \\ "") do
    root
    |> Path.join(relative)
    |> File.ls!()
    |> Enum.flat_map(fn name ->
      path = Path.join(relative, name)
      absolute = Path.join(root, path)

      if File.dir?(absolute), do: unpacked_files(root, path), else: [{path, absolute}]
    end)
  end

  defp normalize(path), do: String.replace(path, "\\", "/")

  defp private_environment(temporary) do
    [
      {"MIX_ENV", "prod"}
      | Enum.map(
          [
            {"MIX_HOME", "mix"},
            {"HEX_HOME", "hex"},
            {"MIX_DEPS_PATH", "deps"},
            {"MIX_BUILD_PATH", "build"}
          ],
          fn {key, name} -> {key, Path.join(temporary, name)} end
        )
    ] ++ [{"MIX_ARCHIVES", Path.join(temporary, "mix/archives")}]
  end

  # Reuse installed Hex code without sharing its writable home/cache with the verifier.
  defp copy_hex_archive(temporary) do
    mix_home = System.get_env("MIX_HOME") || Path.join(System.user_home!(), ".mix")
    archives = System.get_env("MIX_ARCHIVES") || Path.join(mix_home, "archives")
    destination = Path.join(temporary, "mix/archives")
    File.mkdir_p!(destination)

    for source <- Path.wildcard(Path.join(archives, "hex-*")),
        do: File.cp_r!(source, Path.join(destination, Path.basename(source)))
  end

  defp write_consumer(consumer, unpacked) do
    File.mkdir_p!(consumer)

    File.write!(Path.join(consumer, "mix.exs"), """
    defmodule UnicodeSecurityCleanConsumer.MixProject do
      use Mix.Project
      def project do
        [app: :unicode_security_clean_consumer, version: "0.0.0", deps: [{:unicode_security, path: #{inspect(unpacked)}}]]
      end
      def application, do: []
    end
    """)

    File.write!(Path.join(consumer, "consumer.exs"), """
    "18.0.0" = UnicodeSecurity.unicode_version()
    %{release_status: :final, sources: sources} = UnicodeSecurity.data_manifest()
    true = sources != [] and Enum.all?(sources, &(&1.status == :final and &1.version == "18.0.0"))
    %{verdict: :safe, input: "alice-smith"} = UnicodeSecurity.check("alice-smith", type: :username)
    "rn" = UnicodeSecurity.skeleton("m")
    %{class: :single_script_confusable} = UnicodeSecurity.compare("m", "rn")
    true = UnicodeSecurity.conflicts?("m", ["rn"], type: :username)
    %{domain: %{valid_idna?: true, ascii: "xn--bcher-kva.example"}} = UnicodeSecurity.check("bücher.example", type: :domain)
    key = UnicodeSecurity.conflict_key("BÜCHER.example.", type: :domain)
    ^key = UnicodeSecurity.conflict_key("xn--bcher-kva.example", type: :domain)
    %{results: results, duplicates: [%{indexes: [0, 1]}], collisions: [%{indexes: [0, 1, 2]}]} = UnicodeSecurity.check_many(["m", "m", "rn"], type: :username)
    3 = length(results)
    IO.puts("clean consumer passed")
    """)

    :ok
  end
end
