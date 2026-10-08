defmodule UnicodeSecurity.ReleaseCandidatePackageTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias UnicodeSecurity.ReleaseCandidate.{Package, Report, Runner}

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
    assert_receive {:built_tarball, recorded}
    assert metadata.bytes == byte_size(recorded)
    assert metadata.sha256 == Base.encode16(:crypto.hash(:sha256, recorded), case: :lower)
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
    unpacked = Path.join(temporary, "package")
    refute_receive {:command, ["hex.build", "--unpack" | _], _}

    for {key, relative} <- [
          {"MIX_HOME", "mix"},
          {"HEX_HOME", "hex"},
          {"MIX_DEPS_PATH", "deps"},
          {"MIX_BUILD_PATH", "build"}
        ] do
      assert List.keyfind(build_options[:env], key, 0) == {key, Path.join(temporary, relative)}
    end

    assert List.keyfind(build_options[:env], "MIX_ENV", 0) == {"MIX_ENV", "prod"}
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
    for failure <- [:build, :deps, :compile, :run] do
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

    owner = self()

    boundary = fn _, ["hex.build", "--output", archive], _ ->
      File.write!(archive, "not a tarball")
      send(owner, {:bad_archive, archive})
      {"ok", 0}
    end

    assert {:error, %{reason: :unpack}} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert_receive {:bad_archive, archive}
    refute File.exists?(Path.dirname(archive))
  end

  # Breaks: treating a small compressed archive as safe despite excessive inner payload size.
  test "rejects an oversized inner payload before writing unpacked files", context do
    write!(context.unpacked, "README.md", :binary.copy("a", 4_194_305))
    owner = self()

    boundary =
      build_boundary(context, fn args, _ ->
        send(owner, {:size_attempt, args})
        {"ok", 0}
      end)

    assert {:error, %{reason: :unpacked_size, unpacked_bytes: bytes, limit: 4_194_304}} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert bytes > 4_194_304
    assert_receive {:size_attempt, ["hex.build", "--output", archive]}
    refute_receive {:size_attempt, ["deps.get" | _]}
    refute File.exists?(Path.dirname(archive))
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

  test "package cleanup exception retains the original failed command diagnostics", context do
    cleanup = fn path -> raise File.Error, reason: :eacces, action: "remove", path: path end
    boundary = fn _, _, _ -> {"original package build failed", 17} end

    assert {:error, result} =
             Package.verify(context.root,
               cmd: boundary,
               tmp_dir: context.directory,
               cleanup: cleanup
             )

    assert result.status == 17
    assert result.output == "original package build failed"
    assert ["mix", "hex.build", "--output", archive] = result.argv
    assert result.duration_ms >= 0
    assert result.cleanup.reason == :exception
    assert result.cleanup.path == Path.dirname(archive)
    assert result.cleanup.output =~ "permission denied"
  end

  test "successful package verification fails when cleanup returns an error", context do
    boundary = build_boundary(context, fn _, _ -> {"consumer passed", 0} end)
    cleanup = fn path -> {:error, :eacces, path} end

    assert {:error, result} =
             Package.verify(context.root,
               cmd: boundary,
               tmp_dir: context.directory,
               cleanup: cleanup
             )

    assert result.reason == :cleanup_failed
    assert result.consumer == :passed
    assert result.cleanup == %{reason: :eacces, path: Path.dirname(result.archive)}
  end

  test "package cleanup catches exits and throws without replacing original failure", context do
    for {kind, value} <- [exit: :cleanup_exit, throw: :cleanup_throw] do
      cleanup = fn _ -> apply(:erlang, kind, [value]) end

      assert {:error, result} =
               Package.verify(context.root,
                 cmd: fn _, _, _ -> {"original failure", 23} end,
                 tmp_dir: context.directory,
                 cleanup: cleanup
               )

      assert result.status == 23
      assert result.output == "original failure"
      assert result.cleanup.reason == kind
      assert result.cleanup.output == "cleanup #{kind}: :cleanup_#{kind}"
    end
  end

  test "package still cleans temporary state when its command boundary exits or throws",
       context do
    owner = self()

    for {kind, value} <- [exit: :command_exit, throw: :command_throw] do
      boundary = fn _, _, opts ->
        send(owner, {:interrupted_package, opts[:env]})
        apply(:erlang, kind, [value])
      end

      assert {:error, result} =
               Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

      assert result.reason == kind
      assert result.output =~ "command_#{kind}"
      assert_receive {:interrupted_package, env}
      temporary = env |> List.keyfind("MIX_HOME", 0) |> elem(1) |> Path.dirname()
      refute File.exists?(temporary)
    end
  end

  test "runner replaces stale passed evidence and finalizes after package cleanup fails",
       context do
    git!(context.root, ["config", "user.name", "RC cleanup test"])
    git!(context.root, ["config", "user.email", "rc-cleanup@example.invalid"])
    git!(context.root, ["add", "."])
    git!(context.root, ["commit", "--quiet", "-m", "baseline"])
    commit = String.trim(git!(context.root, ["rev-parse", "HEAD"]))
    report_path = Path.join(context.directory, "report.term")
    previous = %{status: :passed, commit: "stale evidence"}
    Report.write!(report_path, previous)
    owner = self()

    cleanup = fn path ->
      File.write!(Path.join(context.root, "cleanup-mutated.txt"), "mutation\n")
      git!(context.root, ["commit", "--quiet", "--allow-empty", "-m", "cleanup changed HEAD"])
      raise File.Error, reason: :eacces, action: "remove", path: path
    end

    package = %{
      name: :package,
      run: fn _ ->
        Package.verify(context.root,
          cmd: fn _, _, _ -> {"original command failure", 29} end,
          tmp_dir: context.directory,
          cleanup: cleanup
        )
      end
    }

    later = %{
      name: :never,
      run: fn _ ->
        send(owner, :unexpected_stage)
        {:ok, %{}}
      end
    }

    outcome =
      try do
        Runner.run(
          root: context.root,
          version: "0.1.0",
          report_path: report_path,
          stages: [package, later]
        )
      rescue
        File.Error ->
          stale = File.read!(report_path) |> :erlang.binary_to_term()
          IO.puts("cleanup escaped and left #{stale.status} evidence for #{stale.commit}")
          {:cleanup_escaped, stale}
      end

    assert {:error, report} = outcome
    assert report.status == :failed
    assert report.commit == commit
    assert report.repository.before == ""
    assert report.repository.after == "?? cleanup-mutated.txt\n"
    refute report.repository.unchanged?

    assert [
             %{name: :package, status: :failed, result: result},
             %{name: :repository_commit, status: :failed, result: identity}
           ] = report.stages

    assert result.status == 29
    assert result.output == "original command failure"
    assert result.cleanup.reason == :exception
    assert identity.expected_commit == commit
    assert identity.actual_commit == String.trim(git!(context.root, ["rev-parse", "HEAD"]))
    assert File.read!(report_path) |> :erlang.binary_to_term() == report
    refute report == previous
    refute_receive :unexpected_stage
  end

  # Breaks: private Hex bootstrapping or a fresh consumer unable to compile the real payload.
  @tag timeout: 120_000
  test "builds and compiles the actual package in a fresh production consumer" do
    assert {:ok, metadata} = Package.verify(Path.expand("."))
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

  # Breaks: inspecting an independently rebuilt tree rather than the recorded archive.
  test "rejects forbidden files present only in the recorded archive", context do
    hex_tar!(context.archive, context.unpacked, [{~c"priv/source.txt", "archive-only data"}])
    recorded = File.read!(context.archive)
    owner = self()

    boundary = fn _, args, _ ->
      case args do
        ["hex.build", "--output", archive] ->
          File.write!(archive, recorded)
          send(owner, {:recorded_archive, archive})

        ["hex.build", "--unpack", "--output", unpacked] ->
          File.cp_r!(context.unpacked, unpacked)

        _ ->
          :ok
      end

      {"ok", 0}
    end

    assert {:error, %{reason: :payload_files, unexpected: ["priv/source.txt"], missing: []}} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert_receive {:recorded_archive, archive}
    refute File.exists?(Path.dirname(archive))
  end

  # Breaks: the consumer using different file bytes from those covered by the digest.
  test "consumer uses the file bytes covered by the recorded archive digest", context do
    write!(context.unpacked, "README.md", "archived release")
    hex_tar!(context.archive, context.unpacked)
    recorded = File.read!(context.archive)
    write!(context.unpacked, "README.md", "independent rebuild")
    owner = self()

    boundary = fn _, args, options ->
      case args do
        ["hex.build", "--output", archive] ->
          File.write!(archive, recorded)

        ["hex.build", "--unpack", "--output", unpacked] ->
          File.cp_r!(context.unpacked, unpacked)

        ["run", "--no-compile", "consumer.exs"] ->
          package = Path.join(Path.dirname(options[:cd]), "package")
          send(owner, {:consumed_readme, File.read!(Path.join(package, "README.md"))})

        _ ->
          :ok
      end

      {"ok", 0}
    end

    assert {:ok, metadata} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert metadata.bytes == byte_size(recorded)
    assert metadata.sha256 == Base.encode16(:crypto.hash(:sha256, recorded), case: :lower)
    assert_receive {:consumed_readme, "archived release"}
    refute File.exists?(Path.dirname(metadata.archive))
  end

  # Breaks: converting a failed authoritative Git command into unstructured exception text.
  test "preserves Git status 128 argv output and duration through verification", context do
    File.rm_rf!(Path.join(context.root, ".git"))
    owner = self()

    boundary =
      build_boundary(context, fn args, _ ->
        send(owner, {:before_git_failure, args})
        {"ok", 0}
      end)

    assert {:error, metadata} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert %{
             argv: ["git", "ls-files", "-z", "--", "lib"],
             status: 128,
             output: output,
             duration_ms: duration
           } = metadata

    assert output =~ "not a git repository"
    assert is_integer(duration) and duration >= 0
    assert_receive {:before_git_failure, ["hex.build", "--output", archive]}
    refute_receive {:before_git_failure, _}
    refute File.exists?(Path.dirname(archive))
  end

  # Breaks: in-memory tar extraction silently omitting archived symbolic links.
  test "rejects archived links instead of silently omitting them from validation", context do
    link = Path.join(context.directory, "extra-link")
    File.ln_s!(Path.join(context.unpacked, "README.md"), link)
    hex_tar!(context.archive, context.unpacked, [{~c"priv/extra-link", String.to_charlist(link)}])
    recorded = File.read!(context.archive)
    owner = self()

    boundary = fn _, args, _ ->
      case args do
        ["hex.build", "--output", archive] ->
          File.write!(archive, recorded)
          send(owner, {:linked_archive, archive})

        _ ->
          :ok
      end

      {"ok", 0}
    end

    assert {:error, %{reason: :unpack}} =
             Package.verify(context.root, cmd: boundary, tmp_dir: context.directory)

    assert_receive {:linked_archive, archive}
    refute File.exists?(Path.dirname(archive))
  end

  defp hex_tar!(archive, unpacked, extras \\ []) do
    contents = archive <> ".contents.tar.gz"

    entries =
      for path <- @files -- ["hex_metadata.config"],
          do: {String.to_charlist(path), File.read!(Path.join(unpacked, path))}

    :ok = :erl_tar.create(String.to_charlist(contents), entries ++ extras, [:compressed])
    compressed = File.read!(contents)
    metadata = File.read!(Path.join(unpacked, "hex_metadata.config"))
    checksum = :crypto.hash(:sha256, "3" <> metadata <> compressed) |> Base.encode16()

    :ok =
      :erl_tar.create(
        String.to_charlist(archive),
        [
          {~c"VERSION", "3"},
          {~c"CHECKSUM", checksum},
          {~c"metadata.config", metadata},
          {~c"contents.tar.gz", compressed}
        ],
        []
      )

    File.rm!(contents)
  end

  test "package test boundary accepts resolved mix.bat and rejects a different executable",
       context do
    executable = "C:\\Program Files\\Beam\\bin\\mix.bat"
    consumer = fn _, _ -> {"command identity accepted", 19} end
    boundary = build_boundary(context, consumer, executable)
    assert {"command identity accepted", 19} = boundary.(executable, [], [])

    assert_raise ExUnit.AssertionError, fn ->
      boundary.("C:\\Other Beam\\bin\\mix.bat", [], [])
    end
  end

  defp build_boundary(context, consumer, expected_executable \\ System.find_executable("mix")) do
    owner = self()

    fn executable, args, options ->
      assert executable == expected_executable
      result = consumer.(args, options)
      complete_build(context, args, owner, result)
      result
    end
  end

  defp complete_build(context, args, owner, {_, 0}) do
    case args do
      ["hex.build", "--output", path] ->
        hex_tar!(path, context.unpacked)
        send(owner, {:built_tarball, File.read!(path)})

      ["hex.build", "--unpack", "--output", path] ->
        File.cp_r!(context.unpacked, path)

      _ ->
        :ok
    end
  end

  defp complete_build(_context, _args, _owner, _result), do: :ok

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
