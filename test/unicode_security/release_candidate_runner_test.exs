defmodule UnicodeSecurity.ReleaseCandidateRunnerTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.ReleaseCandidate.{Command, Report, Runner}

  setup do
    directory =
      Path.join(System.tmp_dir!(), "unicode-security-rc-#{System.unique_integer([:positive])}")

    root = Path.join(directory, "repository with spaces")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(directory) end)
    git!(root, ["init", "--quiet"])
    git!(root, ["config", "user.name", "RC Test"])
    git!(root, ["config", "user.email", "rc-test@example.invalid"])
    File.write!(Path.join(root, "tracked.txt"), "baseline\n")
    git!(root, ["add", "tracked.txt"])
    git!(root, ["commit", "--quiet", "-m", "baseline"])

    %{root: root, report_path: Path.join(directory, "evidence/report.term")}
  end

  # Breaks: reordered stages, dropped metadata, or an incomplete/unreadable report.
  test "runs named stages in order and writes a decodable passing report", context do
    owner = self()
    package = %{bytes: 123, sha256: "package digest"}

    stages = [
      %{
        name: :first,
        run: fn stage_context ->
          send(owner, {:first, stage_context})
          {:ok, %{package: package, seeds: [17, 29], output: "first output"}}
        end
      },
      %{
        name: :second,
        run: fn stage_context ->
          send(owner, {:second, stage_context})
          {:ok, %{output: "second output"}}
        end
      }
    ]

    assert {:ok, report} = Runner.run(options(context, stages))
    commit = String.trim(git!(context.root, ["rev-parse", "HEAD"]))

    assert_receive {:first,
                    %{root: root, version: "0.1.0", commit: ^commit, package: nil, seeds: []}}

    assert root == context.root
    assert_receive {:second, %{package: ^package, seeds: [17, 29]}}
    assert report.status == :passed
    assert report.schema == 1
    assert report.version == "0.1.0"
    assert report.commit == commit
    assert report.package == package
    assert report.seeds == [17, 29]
    assert report.repository == %{before: "", after: "", unchanged?: true}
    assert Enum.map(report.stages, &{&1.name, &1.status}) == [first: :passed, second: :passed]
    assert hd(report.stages).result.output == "first output"
    assert {:ok, _, 0} = DateTime.from_iso8601(report.started_at)
    assert {:ok, _, 0} = DateTime.from_iso8601(report.finished_at)

    assert Enum.sort(Map.keys(report)) ==
             Enum.sort([
               :schema,
               :status,
               :version,
               :commit,
               :started_at,
               :finished_at,
               :stages,
               :repository,
               :package,
               :seeds
             ])

    for stage <- report.stages do
      assert Enum.sort(Map.keys(stage)) == [:duration_ms, :name, :result, :status]
      assert is_integer(stage.duration_ms) and stage.duration_ms >= 0
    end

    assert read_report(context.report_path) == report
  end

  # Breaks: continuing after failure or discarding the child's diagnostics.
  test "stops after the first failed stage and retains its status and output", context do
    owner = self()

    failure = %{
      argv: ["mix", "test"],
      output: "test failure",
      status: 7,
      duration_ms: 3,
      package: %{bytes: 1},
      seeds: [999]
    }

    stages = [
      %{name: :first, run: fn _ -> {:ok, %{output: "ok"}} end},
      %{name: :failing, run: fn _ -> {:error, failure} end},
      %{
        name: :never,
        run: fn _ ->
          send(owner, :unexpected_stage)
          {:ok, %{}}
        end
      }
    ]

    assert {:error, report} = Runner.run(options(context, stages))
    assert report.status == :failed
    assert Enum.map(report.stages, &{&1.name, &1.status}) == [first: :passed, failing: :failed]
    assert List.last(report.stages).result == failure
    assert report.package == nil
    assert report.seeds == []
    assert report.repository == %{before: "", after: "", unchanged?: true}
    refute_receive :unexpected_stage
    assert read_report(context.report_path) == report
  end

  # Breaks: allowing either tracked or untracked changes through preflight.
  test "rejects a dirty repository before running stages", context do
    owner = self()
    File.write!(Path.join(context.root, "tracked.txt"), "changed\n")
    File.write!(Path.join(context.root, "untracked.txt"), "new\n")
    before = git!(context.root, ["status", "--porcelain=v1", "--untracked-files=all"])

    stage = %{
      name: :never,
      run: fn _ ->
        send(owner, :unexpected_stage)
        {:ok, %{}}
      end
    }

    assert {:error, report} = Runner.run(options(context, [stage]))
    assert report.status == :failed
    assert report.stages == []
    assert report.repository == %{before: before, after: before, unchanged?: true}
    refute_receive :unexpected_stage
    assert read_report(context.report_path) == report
  end

  # Breaks: treating a successful child as sufficient despite repository changes.
  test "fails when a successful stage changes repository status", context do
    stage = %{
      name: :mutating,
      run: fn %{root: root} ->
        File.write!(Path.join(root, "new file.txt"), "unexpected change\n")
        {:ok, %{output: "child passed"}}
      end
    }

    assert {:error, report} = Runner.run(options(context, [stage]))
    assert report.status == :failed
    assert [%{name: :mutating, status: :passed}] = report.stages
    assert report.repository == %{before: "", after: "?? \"new file.txt\"\n", unchanged?: false}
    assert read_report(context.report_path) == report
  end

  # Breaks: certifying a different clean commit under the captured source commit.
  test "fails when a successful stage changes HEAD while leaving status clean", context do
    before = String.trim(git!(context.root, ["rev-parse", "HEAD"]))

    stage = %{
      name: :committing,
      run: fn %{root: root} ->
        git!(root, ["commit", "--quiet", "--allow-empty", "-m", "unexpected commit"])
        {:ok, %{output: "child passed"}}
      end
    }

    assert {:error, report} = Runner.run(options(context, [stage]))
    after_commit = String.trim(git!(context.root, ["rev-parse", "HEAD"]))
    refute after_commit == before
    assert report.status == :failed
    assert report.commit == before
    assert report.repository == %{before: "", after: "", unchanged?: false}

    assert [
             %{name: :committing, status: :passed},
             %{name: :repository_commit, status: :failed, result: result}
           ] = report.stages

    assert result.expected_commit == before
    assert result.actual_commit == after_commit
    assert read_report(context.report_path) == report
  end

  # Breaks: reporting success when writing evidence itself dirties the repository.
  test "includes the report file in the final repository comparison", context do
    context = %{context | report_path: Path.join(context.root, "report.term")}
    assert {:error, report} = Runner.run(options(context, []))
    assert report.repository == %{before: "", after: "?? report.term\n", unchanged?: false}
    assert read_report(context.report_path) == report
  end

  # Breaks: leaving partial bytes or temporary files when replacing existing evidence.
  test "removes a partial report through atomic replacement", context do
    File.mkdir_p!(Path.dirname(context.report_path))
    File.write!(context.report_path, "partial report")
    report = %{status: :passed, nested: %{a: 1, b: 2}}

    assert :ok = Report.write!(context.report_path, report)
    assert read_report(context.report_path) == report
    bytes = File.read!(context.report_path)
    assert :ok = Report.write!(context.report_path, report)
    assert File.read!(context.report_path) == bytes
    assert File.ls!(Path.dirname(context.report_path)) == ["report.term"]
  end

  # Breaks: removing a temporary file owned by another VM after exclusive creation fails.
  test "preserves another writer's temporary file on a creation collision", context do
    source = Path.expand("dev/release_candidate/report.ex")

    script = ~S"""
    [path] = System.argv()
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, :erlang.term_to_binary(%{status: :passed, generation: :previous}))
    next = System.unique_integer([:positive, :monotonic]) + 1
    temporary = path <> ".#{next}.tmp"
    File.write!(temporary, "another writer's unfinished bytes")

    try do
      UnicodeSecurity.ReleaseCandidate.Report.write!(path, %{status: :passed, generation: :next})
    rescue
      error in File.Error ->
        if error.reason != :eexist, do: reraise(error, __STACKTRACE__)
    end

    if File.read(temporary) != {:ok, "another writer's unfinished bytes"}, do: System.halt(1)
    if File.read!(path) |> :erlang.binary_to_term() != %{status: :passed, generation: :previous}, do: System.halt(2)
    IO.puts("previous report and other writer preserved")
    """

    assert {"previous report and other writer preserved\n", 0} =
             System.cmd(
               System.find_executable("elixir"),
               ["-r", source, "-e", script, context.report_path],
               stderr_to_stdout: true
             )
  end

  # Breaks: publishing in-place writes that let independent readers observe partial bytes.
  # Windows rename may briefly remove the destination; :enoent is permitted during replacement.
  test "concurrent raw readers see only complete reports or a missing destination", context do
    reports =
      for generation <- 1..40,
          do: %{generation: generation, payload: String.duplicate("report bytes", 10_000)}

    assert :ok = Report.write!(context.report_path, hd(reports))
    allowed = MapSet.new(reports)
    owner = self()

    writer =
      Task.async(fn ->
        receive do
          :start ->
            for report <- reports, do: Report.write!(context.report_path, report)
            send(owner, :reports_written)
        end
      end)

    send(writer.pid, :start)
    observed = read_while_writing(context.report_path, allowed, 0)
    assert observed > 0
    Task.await(writer, 10_000)
    assert read_report(context.report_path) == List.last(reports)
    assert File.ls!(Path.dirname(context.report_path)) == ["report.term"]
  end

  # Breaks: shell expansion or splitting path arguments at the process boundary.
  test "passes Windows-style paths as argv without shell interpolation", context do
    args = ["C:\\Users\\Release Candidate\\archive.tar", "$(touch injected)", "a&b"]
    owner = self()

    boundary = fn executable, argv, opts ->
      send(owner, {:process, executable, argv, opts})
      {"captured output", 0}
    end

    assert {:ok, result} =
             Command.run(context.root, "git", args, cmd: boundary, env: [{"RC_ENV", "yes"}])

    assert_receive {:process, executable, ^args, process_opts}
    assert executable == System.find_executable("git")
    assert process_opts[:cd] == context.root
    assert process_opts[:stderr_to_stdout] == true
    assert process_opts[:env] == [{"RC_ENV", "yes"}]
    assert result.argv == ["git" | args]
    assert result.output == "captured output"
    assert result.status == 0
    assert is_integer(result.duration_ms) and result.duration_ms >= 0
    assert Enum.sort(Map.keys(result)) == [:argv, :duration_ms, :output, :status]
    refute File.exists?(Path.join(context.root, "injected"))
  end

  # Breaks: an absent executable raising instead of producing a structured failure.
  test "returns a structured failure when the executable cannot be found", context do
    assert {:error, result} =
             Command.run(context.root, "unicode_security_missing_executable", ["arg"])

    assert result.argv == ["unicode_security_missing_executable", "arg"]
    assert result.status == 127
    assert result.output =~ "unicode_security_missing_executable"
    assert is_integer(result.duration_ms) and result.duration_ms >= 0
  end

  # Breaks: returning success for a nonzero child or losing stderr diagnostics.
  test "captures output and exit status from a real failing process", context do
    assert {:error, result} = Command.run(context.root, "git", ["show", "missing-ref"])
    assert result.status != 0
    assert result.output =~ "missing-ref"
    assert result.argv == ["git", "show", "missing-ref"]
  end

  # Breaks: losing the root working directory for real processes.
  test "executes a real command in the requested repository", context do
    assert {:ok, result} = Command.run(context.root, "git", ["rev-parse", "HEAD"])
    assert result.status == 0
    assert result.output == git!(context.root, ["rev-parse", "HEAD"])
  end

  defp options(context, stages),
    do: [root: context.root, version: "0.1.0", report_path: context.report_path, stages: stages]

  defp read_report(path), do: path |> File.read!() |> :erlang.binary_to_term()

  defp read_while_writing(path, allowed, observed) do
    receive do
      :reports_written -> observed
    after
      0 ->
        case raw_read(path) do
          {:ok, bytes} ->
            assert MapSet.member?(allowed, :erlang.binary_to_term(bytes))
            read_while_writing(path, allowed, observed + 1)

          {:error, :enoent} ->
            read_while_writing(path, allowed, observed)
        end
    end
  end

  defp raw_read(path) do
    case :file.open(String.to_charlist(path), [:read, :binary, :raw]) do
      {:ok, file} ->
        try do
          :file.read(file, 1_000_000)
        after
          :file.close(file)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp git!(root, args) do
    {output, 0} = System.cmd("git", args, cd: root, stderr_to_stdout: true)
    output
  end
end
