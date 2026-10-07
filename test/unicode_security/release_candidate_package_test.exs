defmodule UnicodeSecurity.ReleaseCandidatePackageTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias UnicodeSecurity.ReleaseCandidate.Package

  @files Enum.sort(
           ~w(.formatter.exs CHANGELOG.md LICENSE README.md THIRD_PARTY_NOTICES.md hex_metadata.config mix.exs lib/example.ex lib/nested/child.ex)
         )

  setup do
    directory =
      Path.join(
        System.tmp_dir!(),
        "unicode-security-package-#{System.unique_integer([:positive])}"
      )

    root = Path.join(directory, "repository with spaces")
    unpacked = Path.join(directory, "unpacked")
    archive = Path.join(directory, "package.tar")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(directory) end)
    git!(root, ["init", "--quiet"])

    for path <- @files do
      write!(root, path, "")
      write!(unpacked, path, "")
    end

    write!(root, "lib/ignored.txt", "not a runtime module")
    git!(root, ["add", "lib"])
    File.write!(archive, "abc")
    %{root: root, unpacked: unpacked, archive: archive, directory: directory}
  end

  # Breaks: including untracked/non-Elixir runtime files or omitting public files.
  test "accepts tracked runtime modules and the seven package root files", context do
    assert Package.expected_files(context.root) == @files
    assert {:ok, metadata} = validate(context)
    assert metadata.files == @files
    assert metadata.archive == context.archive
    assert metadata.bytes == 3
    assert metadata.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  end

  # Breaks: deriving the runtime allowlist from disk instead of the Git index.
  test "rejects an untracked module included under lib", context do
    write!(context.root, "lib/untracked.ex", "")
    write!(context.unpacked, "lib/untracked.ex", "")
    assert {:error, metadata} = validate(context)
    assert metadata.unexpected == ["lib/untracked.ex"]
    assert metadata.missing == []
  end

  # Breaks: allowing extra files, including dotfiles, anywhere in the payload.
  test "rejects source fixtures development tests scripts plans and build artifacts", context do
    extras =
      ~w(priv/unicode/source.txt test/fixtures/example.txt dev/check.ex test/example_test.exs scripts/check.sh docs/superpowers/plans/example.md _build/prod/lib/example.beam .hidden)

    for path <- extras, do: write!(context.unpacked, path, "")
    assert {:error, metadata} = validate(context)
    assert metadata.unexpected == Enum.sort(extras)
    assert metadata.missing == []
  end

  # Breaks: accepting a subset of the tracked modules.
  test "reports missing tracked runtime files", context do
    File.rm!(Path.join(context.unpacked, "lib/nested/child.ex"))
    assert {:error, metadata} = validate(context)
    assert metadata.unexpected == []
    assert metadata.missing == ["lib/nested/child.ex"]
  end

  # Breaks: comparing host separators rather than normalized package paths.
  test "normalizes Windows separators before comparing paths", context do
    File.rm!(Path.join(context.unpacked, "lib/nested/child.ex"))
    write!(context.unpacked, "lib\\nested\\child.ex", "")
    assert {:ok, metadata} = validate(context)
    assert metadata.files == @files
  end

  # Breaks: off-by-one limits, swapped budgets, or ignoring nested file sizes.
  test "rejects archives over one MiB and unpacked payloads over four MiB", context do
    File.write!(context.archive, :binary.copy("a", 1_048_576))
    write!(context.unpacked, "lib/nested/child.ex", :binary.copy("b", 4_194_304))
    assert {:ok, _} = validate(context)

    File.write!(context.archive, :binary.copy("a", 1_048_577))

    assert {:error, %{reason: :archive_size, bytes: 1_048_577, limit: 1_048_576}} =
             validate(context)

    File.write!(context.archive, "abc")
    write!(context.unpacked, "README.md", "b")

    assert {:error, %{reason: :unpacked_size, unpacked_bytes: 4_194_305, limit: 4_194_304}} =
             validate(context)
  end

  # Breaks: skipped public API checks or a consumer that cannot execute its assertions.
  test "consumer source exercises final metadata identifiers domains conflicts and batches",
       context do
    owner = self()

    boundary =
      build_boundary(context, fn args, options ->
        if args == ["run", "--no-compile", "consumer.exs"] do
          source = File.read!(Path.join(options[:cd], "consumer.exs"))

          {_, calls} =
            Macro.prewalk(Code.string_to_quoted!(source), [], fn
              {{:., _, [{:__aliases__, _, [:UnicodeSecurity]}, name]}, _, arguments} = node,
              calls ->
                {values, _} = Code.eval_quoted(arguments)
                {node, [{name, values} | calls]}

              node, calls ->
                {node, calls}
            end)

          send(owner, {:consumer_calls, calls})

          assert capture_io(fn -> Code.eval_file(Path.join(options[:cd], "consumer.exs")) end) ==
                   "clean consumer passed\n"
        end

        {"consumer passed", 0}
      end)

    assert {:ok, metadata} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert metadata.consumer == :passed
    assert metadata.files == @files
    assert metadata.bytes == 3
    assert metadata.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    refute File.exists?(Path.dirname(metadata.archive))
    assert_receive {:consumer_calls, calls}

    assert Enum.sort(calls) ==
             Enum.sort([
               {:unicode_version, []},
               {:data_manifest, []},
               {:check, ["alice-smith", [type: :username]]},
               {:check, ["bücher.example", [type: :domain]]},
               {:skeleton, ["m"]},
               {:compare, ["m", "rn"]},
               {:conflicts?, ["m", ["rn"], [type: :username]]},
               {:conflict_key, ["BÜCHER.example.", [type: :domain]]},
               {:conflict_key, ["xn--bcher-kva.example", [type: :domain]]},
               {:check_many, [["m", "m", "rn"], [type: :username]]}
             ])
  end

  # Breaks: output paths outside the owned root, reused cache directories, wrong Mix env/dependency.
  test "uses private Mix Hex deps and build directories inside the temporary root", context do
    owner = self()

    boundary =
      build_boundary(context, fn args, options ->
        send(owner, {:command, args, options})

        if args == ["deps.get", "--only", "prod"] do
          send(owner, {:project, File.read!(Path.join(options[:cd], "mix.exs"))})
        end

        {"ok", 0}
      end)

    assert {:ok, metadata} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    temporary = Path.dirname(metadata.archive)
    assert Path.dirname(temporary) == context.directory
    assert Path.basename(metadata.archive) == "package.tar"
    assert_receive {:command, ["hex.build", "--output", archive], build_options}
    assert archive == metadata.archive
    assert build_options[:cd] == context.root
    assert_receive {:command, ["hex.build", "--unpack", "--output", unpacked], unpack_options}
    assert unpacked == Path.join(temporary, "package")
    assert unpack_options[:cd] == context.root

    for {key, relative} <- [
          {"MIX_HOME", "mix"},
          {"HEX_HOME", "hex"},
          {"MIX_DEPS_PATH", "deps"},
          {"MIX_BUILD_PATH", "build"}
        ] do
      assert List.keyfind(build_options[:env], key, 0) == {key, Path.join(temporary, relative)}
    end

    assert List.keyfind(build_options[:env], "MIX_ENV", 0) == {"MIX_ENV", "prod"}
    assert unpack_options[:env] == build_options[:env]
    assert_receive {:project, project}
    assert project =~ "{:unicode_security, path: #{inspect(unpacked)}}"

    for args <- [
          ["deps.get", "--only", "prod"],
          ["compile", "--warnings-as-errors"],
          ["run", "--no-compile", "consumer.exs"]
        ] do
      assert_receive {:command, ^args, options}
      assert options[:cd] == Path.join(temporary, "consumer")
      assert options[:env] == build_options[:env]
    end

    refute File.exists?(temporary)
  end

  # Breaks: continuing after command failure, losing diagnostics, or leaking temporary state.
  test "removes the temporary root when build unpack or consumer execution fails", context do
    for failure <- [:build, :unpack, :deps, :compile, :run] do
      owner = self()

      boundary =
        build_boundary(context, fn args, options ->
          send(owner, {:attempt, args, options[:env]})
          if command_stage(args) == failure, do: {"#{failure} failed", 19}, else: {"ok", 0}
        end)

      assert {:error, metadata} =
               Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

      assert metadata.status == 19
      assert metadata.output == "#{failure} failed"
      assert metadata.argv |> tl() |> command_stage() == failure
      assert metadata.duration_ms >= 0
      attempts = collect_attempts([])
      assert attempts |> List.last() |> elem(0) |> command_stage() == failure
      {_, env} = hd(attempts)
      temporary = env |> List.keyfind("MIX_HOME", 0) |> elem(1) |> Path.dirname()
      refute File.exists?(temporary)
    end
  end

  # Breaks: rescuing an exception without releasing files owned by the verifier.
  test "cleans up when the command boundary raises", context do
    owner = self()

    boundary = fn _, _, options ->
      send(owner, {:raised_env, options[:env]})
      raise "boundary failure"
    end

    assert {:error, %{reason: :exception, output: output}} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert output =~ "boundary failure"
    assert_receive {:raised_env, env}
    temporary = env |> List.keyfind("MIX_HOME", 0) |> elem(1) |> Path.dirname()
    refute File.exists?(temporary)
  end

  # Breaks: private Hex bootstrapping or a fresh consumer unable to compile the real payload.
  @tag timeout: 120_000
  test "builds and compiles the actual package in a fresh production consumer", context do
    assert {:ok, metadata} = Package.verify(Path.expand("."), tmp_dir: context.directory)
    assert metadata.consumer == :passed
    assert metadata.bytes > 0 and metadata.bytes <= 1_048_576
    assert "lib/unicode_security.ex" in metadata.files
    assert "hex_metadata.config" in metadata.files
    refute Enum.any?(metadata.files, &String.starts_with?(&1, "dev/"))
    refute File.exists?(Path.dirname(metadata.archive))
  end

  # Breaks: using VM-local counters as globally unique temporary-directory names.
  test "independent verifier processes use different temporary roots", context do
    script = """
    Code.require_file(#{inspect(Path.expand("dev/release_candidate/command.ex"))})
    Code.require_file(#{inspect(Path.expand("dev/release_candidate/package.ex"))})
    boundary = fn _, _, options ->
      {_, mix_home} = List.keyfind(options[:env], "MIX_HOME", 0)
      IO.puts(Path.dirname(mix_home))
      {"stopped", 17}
    end
    {:error, %{status: 17}} = UnicodeSecurity.ReleaseCandidate.Package.verify(#{inspect(context.root)}, tmp_dir: #{inspect(context.directory)}, cmd: boundary)
    """

    roots =
      for _ <- 1..2 do
        {output, 0} =
          System.cmd("elixir", ["--erl", "+S 1", "-e", script], stderr_to_stdout: true)

        String.trim(output)
      end

    assert length(Enum.uniq(roots)) == 2
    for root <- roots, do: refute(File.exists?(root))
  end

  defp build_boundary(context, consumer) do
    fn executable, args, options ->
      assert Path.basename(executable) == "mix"
      result = consumer.(args, options)

      if elem(result, 1) == 0 do
        case args do
          ["hex.build", "--output", path] -> File.write!(path, "abc")
          ["hex.build", "--unpack", "--output", path] -> File.cp_r!(context.unpacked, path)
          _ -> :ok
        end
      end

      result
    end
  end

  defp command_stage(["hex.build", "--unpack" | _]), do: :unpack
  defp command_stage(["hex.build" | _]), do: :build
  defp command_stage(["deps.get" | _]), do: :deps
  defp command_stage(["compile" | _]), do: :compile
  defp command_stage(["run" | _]), do: :run

  defp collect_attempts(attempts) do
    receive do
      {:attempt, args, env} -> collect_attempts(attempts ++ [{args, env}])
    after
      0 -> attempts
    end
  end

  defp validate(context),
    do: Package.validate_payload(context.root, context.archive, context.unpacked)

  defp write!(root, path, contents) do
    target = Path.join(root, path)
    File.mkdir_p!(Path.dirname(target))
    File.write!(target, contents)
  end

  defp git!(root, args) do
    {output, 0} = System.cmd("git", args, cd: root, stderr_to_stdout: true)
    output
  end
end
