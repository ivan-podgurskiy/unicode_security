defmodule UnicodeSecurity.ReleaseCandidateTest do
  use ExUnit.Case, async: true

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

  # Breaks: dropping the package verifier's metadata at composition/runner boundary.
  test "includes package metadata in the final report", %{root: root} do
    package = %{
      archive: "/temporary/package.tar",
      bytes: 321,
      sha256: String.duplicate("a", 64),
      files: ["mix.exs"],
      consumer: :passed
    }

    stage = %{name: :package, run: fn _ -> {:ok, %{package: package}} end}
    assert {:ok, report} = ReleaseCandidate.run(root: root, version: "0.1.0", stages: [stage])
    assert report.package == package

    assert report.stages == [
             %{
               name: :package,
               status: :passed,
               duration_ms: hd(report.stages).duration_ms,
               result: %{package: package}
             }
           ]
  end

  # Breaks: placing evidence in a nonignored path and invalidating a clean run.
  test "defaults the report to ignored tmp release-candidate term", %{root: root} do
    assert {:ok, report} = ReleaseCandidate.run(root: root, version: "0.1.0", stages: [])
    assert read_report(Path.join(root, "tmp/release-candidate.term")) == report
    assert report.repository == %{before: "", after: "", unchanged?: true}
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

  defp read_report(path), do: path |> File.read!() |> :erlang.binary_to_term()

  defp git!(root, args) do
    {output, 0} = System.cmd("git", args, cd: root, stderr_to_stdout: true)
    output
  end
end
