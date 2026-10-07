defmodule UnicodeSecurity.ReleaseCandidate do
  @moduledoc false

  alias UnicodeSecurity.ReleaseCandidate.{Command, Package, Runner}

  @property_seeds [18, 34, 36, 180_034, 390_036]
  @property_files ~w(
    test/unicode_security/audit_test.exs
    test/unicode_security/batch_test.exs
    test/unicode_security/check_test.exs
    test/unicode_security/conflicts_test.exs
    test/unicode_security/confusables_test.exs
    test/unicode_security/domain_key_test.exs
    test/unicode_security/pair_test.exs
    test/unicode_security/punycode_test.exs
    test/unicode_security/skeleton_trace_test.exs
  )

  @spec run(keyword()) :: {:ok, map()} | {:error, map()}
  def run(opts \\ []) do
    root = opts |> Keyword.get(:root, File.cwd!()) |> Path.expand()

    version =
      Keyword.get_lazy(opts, :version, fn ->
        Application.spec(:unicode_security, :vsn) |> to_string()
      end)

    path = Path.expand(Keyword.get(opts, :report_path, "tmp/release-candidate.term"), root)
    stages = Keyword.get_lazy(opts, :stages, &default_stages/0)
    Runner.run(root: root, version: version, report_path: path, stages: stages)
  end

  @spec property_seeds() :: [integer()]
  def property_seeds, do: @property_seeds

  @spec default_stages() :: [map()]
  def default_stages do
    [
      command(:compile, ["compile", "--warnings-as-errors"]),
      command(:format, ["format", "--check-formatted"]),
      command(:sources, ["run", "scripts/fetch_unicode_data.exs"]),
      command(:generated, ["run", "scripts/check_generated.exs"]),
      command(:release_data, ["run", "scripts/check_release_data.exs"]),
      command(:coverage, ["test", "--cover", "--warnings-as-errors"], "test"),
      command(:credo, ["credo", "--strict"]),
      command(:dialyzer, ["dialyzer", "--format", "github"]),
      command(:docs, ["docs", "--warnings-as-errors"])
    ] ++
      Enum.map([0, 2, 3, 4], fn milestone ->
        command(benchmark_name(milestone), ["run", "bench/milestone_#{milestone}.exs"])
      end) ++
      Enum.map(@property_seeds, &property_stage/1) ++
      [package_stage(), command(:hex_publish_dry_run, ["hex.publish", "--dry-run"])]
  end

  defp command(name, args, environment \\ "dev") do
    env = [{"MIX_ENV", environment}]

    %{
      name: name,
      args: args,
      env: env,
      run: fn context ->
        opts = Keyword.put(Map.get(context, :command_opts, []), :env, env)
        Command.run(context.root, "mix", args, opts)
      end
    }
  end

  defp property_stage(seed) do
    args =
      ["test" | @property_files] ++ ["--warnings-as-errors", "--seed", Integer.to_string(seed)]

    stage = command(property_name(seed), args, "test")

    %{
      stage
      | run: fn context ->
          {outcome, result} = stage.run.(context)
          result = Map.put(result, :seed, seed)

          result =
            if outcome == :ok, do: Map.put(result, :seeds, context.seeds ++ [seed]), else: result

          {outcome, result}
        end
    }
    |> Map.put(:seed, seed)
  end

  defp package_stage do
    %{
      name: :package,
      env: [{"MIX_ENV", "dev"}],
      run: fn context ->
        case Package.verify(context.root) do
          {:ok, package} -> {:ok, %{package: package}}
          {:error, result} -> {:error, result}
        end
      end
    }
  end

  defp benchmark_name(0), do: :benchmark_0
  defp benchmark_name(2), do: :benchmark_2
  defp benchmark_name(3), do: :benchmark_3
  defp benchmark_name(4), do: :benchmark_4
  defp property_name(18), do: :property_18
  defp property_name(34), do: :property_34
  defp property_name(36), do: :property_36
  defp property_name(180_034), do: :property_180034
  defp property_name(390_036), do: :property_390036
end
