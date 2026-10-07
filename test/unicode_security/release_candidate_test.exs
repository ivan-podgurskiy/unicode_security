defmodule UnicodeSecurity.ReleaseCandidateTest do
  use ExUnit.Case, async: false

  alias UnicodeSecurity.ReleaseCandidate

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "unicode-security-composition-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    git!(root, ["init", "--quiet"])
    git!(root, ["config", "user.name", "RC Test"])
    git!(root, ["config", "user.email", "rc-test@example.invalid"])
    File.write!(Path.join(root, ".gitignore"), "/tmp/\n")
    git!(root, ["add", ".gitignore"])
    git!(root, ["commit", "--quiet", "-m", "baseline"])
    %{root: root}
  end

  # Breaks: omitting or reordering any required gate.
  test "defines the complete release stage order" do
    assert Enum.map(ReleaseCandidate.default_stages(), & &1.name) == [
             :compile,
             :format,
             :sources,
             :generated,
             :release_data,
             :coverage,
             :credo,
             :dialyzer,
             :docs,
             :benchmark_0,
             :benchmark_2,
             :benchmark_3,
             :benchmark_4,
             :property_18,
             :property_34,
             :property_36,
             :property_180034,
             :property_390036,
             :package,
             :hex_publish_dry_run
           ]
  end

  # Breaks: missing a property file or using nondeterministic seeds.
  test "uses five fixed property seeds and every property test file" do
    assert ReleaseCandidate.property_seeds() == [18, 34, 36, 180_034, 390_036]

    files =
      Path.wildcard("test/**/*_test.exs")
      |> Enum.filter(&Regex.match?(~r/^\s*use ExUnitProperties\b/m, File.read!(&1)))
      |> Enum.sort()

    assert length(files) == 9
    properties = Enum.filter(ReleaseCandidate.default_stages(), &Map.has_key?(&1, :seed))
    assert Enum.map(properties, & &1.seed) == [18, 34, 36, 180_034, 390_036]

    for stage <- properties do
      assert stage.args ==
               ["test" | files] ++
                 ["--warnings-as-errors", "--seed", Integer.to_string(stage.seed)]
    end
  end

  # Breaks: inheriting the caller's MIX_ENV or weakening quality commands.
  test "assigns dev and test environments explicitly per command" do
    stages = ReleaseCandidate.default_stages()

    for stage <- stages do
      expected = if stage.name == :coverage or Map.has_key?(stage, :seed), do: "test", else: "dev"
      assert stage.env == [{"MIX_ENV", expected}]
      assert is_function(stage.run, 1)
    end

    by_name = Map.new(stages, &{&1.name, &1})
    assert by_name.compile.args == ["compile", "--warnings-as-errors"]
    assert by_name.format.args == ["format", "--check-formatted"]
    assert by_name.coverage.args == ["test", "--cover", "--warnings-as-errors"]
    assert by_name.credo.args == ["credo", "--strict"]
    assert by_name.dialyzer.args == ["dialyzer", "--format", "github"]
    assert by_name.docs.args == ["docs", "--warnings-as-errors"]
    assert by_name.hex_publish_dry_run.args == ["hex.publish", "--dry-run"]

    for {name, path} <- [
          sources: "scripts/fetch_unicode_data.exs",
          generated: "scripts/check_generated.exs",
          release_data: "scripts/check_release_data.exs",
          benchmark_0: "bench/milestone_0.exs",
          benchmark_2: "bench/milestone_2.exs",
          benchmark_3: "bench/milestone_3.exs",
          benchmark_4: "bench/milestone_4.exs"
        ] do
      assert by_name[name].args == ["run", path]
    end
  end

  # Breaks: bypassing the real package verifier or dropping its archive evidence.
  test "includes package metadata in the final report", %{root: root} do
    owner = self()
    bytes = package_fixture!(root)

    boundary = fn _executable, args, opts ->
      send(owner, {:package_command, args, opts})

      case args do
        ["hex.build", "--output", archive] ->
          assert opts[:cd] == root
          File.write!(archive, bytes)

        ["run", "--no-compile", "consumer.exs"] ->
          unpacked = Path.join(Path.dirname(opts[:cd]), "package")
          assert File.read!(Path.join(unpacked, "README.md")) == "fixture README.md\n"

        _ ->
          :ok
      end

      {"package boundary passed", 0}
    end

    stage = package_stage(cmd: boundary, tmp_dir: Path.join(root, "tmp"))
    assert {:ok, report} = ReleaseCandidate.run(root: root, stages: [stage])
    assert report.version == UnicodeSecurity.MixProject.project()[:version]
    assert report.package.bytes == byte_size(bytes)
    assert report.package.sha256 == Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

    assert report.package.files ==
             Enum.sort(
               ~w(.formatter.exs CHANGELOG.md LICENSE README.md THIRD_PARTY_NOTICES.md hex_metadata.config mix.exs)
             )

    assert report.package.consumer == :passed
    assert [%{name: :package, status: :passed, result: %{package: package}}] = report.stages
    assert package == report.package
    assert report.repository.unchanged?
    refute File.exists?(Path.dirname(package.archive))
    assert_receive {:package_command, ["hex.build", "--output", archive], build_opts}
    assert archive == package.archive
    assert List.keyfind(build_opts[:env], "MIX_ENV", 0) == {"MIX_ENV", "prod"}

    for args <- [
          ["deps.get", "--only", "prod"],
          ["compile", "--warnings-as-errors"],
          ["run", "--no-compile", "consumer.exs"]
        ] do
      assert_receive {:package_command, ^args, opts}
      assert opts[:env] == build_opts[:env]
      assert opts[:cd] == Path.join(Path.dirname(archive), "consumer")
    end
  end

  # Breaks: converting verifier failures into package success or discarding diagnostics.
  test "preserves real package-stage failures and stops the composed gate", %{root: root} do
    owner = self()

    boundary = fn _executable, args, opts ->
      send(owner, {:failed_package_command, args, opts})
      {"package build failed", 23}
    end

    stage = package_stage(cmd: boundary, tmp_dir: Path.join(root, "tmp"))

    later = %{
      name: :never,
      run: fn _ ->
        send(owner, :unexpected_stage)
        {:ok, %{}}
      end
    }

    assert {:error, report} = ReleaseCandidate.run(root: root, stages: [stage, later])
    assert report.package == nil
    assert [%{name: :package, status: :failed, result: result}] = report.stages
    assert result.status == 23
    assert result.output == "package build failed"
    assert ["mix", "hex.build", "--output", archive] = result.argv
    assert_receive {:failed_package_command, ["hex.build", "--output", ^archive], opts}
    assert opts[:cd] == root
    refute File.exists?(Path.dirname(archive))
    refute_receive :unexpected_stage
    assert report.repository.unchanged?
  end

  # Breaks: placing evidence in a nonignored path and invalidating a clean run.
  test "defaults the report to ignored tmp release-candidate term", %{root: root} do
    assert {:ok, report} = ReleaseCandidate.run(root: root, stages: [])
    assert read_report(Path.join(root, "tmp/release-candidate.term")) == report
    assert report.repository == %{before: "", after: "", unchanged?: true}
  end

  # Breaks: the zero-argument entry point skipping defaults or dirty preflight.
  # File.cd! changes VM-wide cwd, so this test module is deliberately synchronous.
  test "zero-argument entry point uses the current repository and default version", %{root: root} do
    File.write!(Path.join(root, "dirty.txt"), "dirty\n")
    assert {:error, report} = File.cd!(root, fn -> ReleaseCandidate.run() end)
    assert report.version == UnicodeSecurity.MixProject.project()[:version]
    assert report.stages == []
    assert report.repository.before == "?? dirty.txt\n"
    assert read_report(Path.join(root, "tmp/release-candidate.term")) == report
  end

  # Breaks: exposing no runnable alias or broadening the release package.
  test "mix project exposes the rc alias without changing package files" do
    config = UnicodeSecurity.MixProject.project()
    assert config[:aliases][:rc] == "run scripts/release_candidate.exs"

    assert config[:package][:files] ==
             ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md THIRD_PARTY_NOTICES.md)

    assert File.regular?("scripts/release_candidate.exs")
  end

  # Breaks: losing the report override or accepting extra CLI arguments.
  test "CLI rejects unknown positional and incomplete arguments before running stages", %{
    root: root
  } do
    script = Path.expand("scripts/release_candidate.exs")
    code = Path.expand("_build/test/lib/unicode_security/ebin")

    invocation = [
      "-pa",
      code,
      "-e",
      "Application.load(:unicode_security); Code.require_file(#{inspect(script)})",
      "--"
    ]

    File.write!(Path.join(root, "dirty.txt"), "dirty\n")

    for args <- [
          ["--unknown"],
          ["--report", "--unknown"],
          ["--report", ""],
          ["positional"],
          ["--report"],
          ["--report", "one", "--report", "two"]
        ] do
      {output, status} =
        System.cmd("elixir", invocation ++ args, cd: root, stderr_to_stdout: true)

      assert status != 0
      assert output =~ "usage: mix rc [--report PATH]"
    end

    # Execute the script in a dirty temporary repository with the compiled real modules.
    report_path = Path.join(root, "tmp/custom report.term")

    {output, status} =
      System.cmd(
        "elixir",
        [
          "-pa",
          code,
          "-e",
          "Application.load(:unicode_security); Code.require_file(#{inspect(script)})",
          "--",
          "--report",
          report_path
        ],
        cd: root,
        stderr_to_stdout: true
      )

    assert status == 1
    assert output =~ "dirty.txt"
    assert output =~ "0.1.0"
    assert read_report(report_path).stages == []
  end

  # Breaks: descriptor/closure drift, implicit environments, or losing seed reproduction details.
  test "executes command descriptors and retains seeded command failures", %{root: root} do
    owner = self()

    boundary = fn _executable, args, opts ->
      send(owner, {:command, args, opts})
      {"smoke output", 0}
    end

    context = %{root: root, seeds: [], command_opts: [cmd: boundary]}

    for stage <- ReleaseCandidate.default_stages(), stage.name != :package do
      assert {:ok, result} = stage.run.(context)
      assert_receive {:command, args, opts}
      assert args == stage.args
      assert opts[:env] == stage.env
      assert result.argv == ["mix" | args]
      if Map.has_key?(stage, :seed), do: assert(result.seeds == [stage.seed])
    end

    property = Enum.find(ReleaseCandidate.default_stages(), &(&1.name == :property_34))
    assert {:ok, result} = property.run.(%{context | seeds: [18]})
    assert result.seeds == [18, 34]
    failure = %{context | command_opts: [cmd: fn _, _, _ -> {"seed failed", 9} end]}
    assert {:error, result} = property.run.(failure)
    assert result.seed == 34
    assert result.status == 9
    assert result.output == "seed failed"
  end

  defp package_stage(options) do
    stage = Enum.find(ReleaseCandidate.default_stages(), &(&1.name == :package))
    %{stage | run: fn context -> stage.run.(Map.put(context, :package_opts, options)) end}
  end

  defp package_fixture!(root) do
    temporary = Path.join(root, "tmp")
    File.mkdir_p!(temporary)
    contents = Path.join(temporary, "contents.tar.gz")
    archive = Path.join(temporary, "fixture.tar")

    files =
      for path <-
            ~w(.formatter.exs CHANGELOG.md LICENSE README.md THIRD_PARTY_NOTICES.md mix.exs),
          do: {String.to_charlist(path), "fixture #{path}\n"}

    :ok = :erl_tar.create(String.to_charlist(contents), files, [:compressed])
    compressed = File.read!(contents)
    metadata = "[].\n"
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

    File.read!(archive)
  end

  defp read_report(path), do: path |> File.read!() |> :erlang.binary_to_term()

  defp git!(root, args) do
    {output, 0} = System.cmd("git", args, cd: root, stderr_to_stdout: true)
    output
  end
end
