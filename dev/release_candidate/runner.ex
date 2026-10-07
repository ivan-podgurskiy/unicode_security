defmodule UnicodeSecurity.ReleaseCandidate.Runner do
  @moduledoc false

  alias UnicodeSecurity.ReleaseCandidate.{Command, Report}

  @status_args ["status", "--porcelain=v1", "--untracked-files=all"]

  @spec run(keyword()) :: {:ok, map()} | {:error, map()}
  def run(opts) do
    root = Keyword.fetch!(opts, :root)
    version = Keyword.fetch!(opts, :version)
    report_path = Keyword.fetch!(opts, :report_path)
    stages = Keyword.fetch!(opts, :stages)

    report = %{
      schema: 1,
      status: :failed,
      version: version,
      commit: "",
      started_at: timestamp(),
      finished_at: "",
      stages: [],
      repository: %{before: "", after: "", unchanged?: false},
      package: nil,
      seeds: []
    }

    report =
      with {:ok, commit} <- Command.run(root, "git", ["rev-parse", "HEAD"]),
           {:ok, before} <- Command.run(root, "git", @status_args) do
        report = %{
          report
          | commit: String.trim(commit.output),
            repository: %{
              before: before.output,
              after: before.output,
              unchanged?: true
            }
        }

        if before.output == "" do
          context = %{
            root: root,
            version: version,
            commit: report.commit,
            package: nil,
            seeds: []
          }

          execute(stages, context, %{report | status: :passed})
        else
          report
        end
      else
        {:error, result} ->
          %{report | stages: [entry(:preflight, :failed, result, result.duration_ms)]}
      end

    finalize(root, report_path, report)
  end

  defp execute(stages, context, report) do
    Enum.reduce_while(stages, {context, report}, fn %{name: name, run: run}, {context, report} ->
      started = System.monotonic_time(:millisecond)
      {outcome, result} = run.(context)
      duration = System.monotonic_time(:millisecond) - started
      status = if outcome == :ok, do: :passed, else: :failed
      report = %{report | stages: report.stages ++ [entry(name, status, result, duration)]}

      case outcome do
        :ok ->
          context = Map.merge(context, Map.take(result, [:package, :seeds]))
          report = %{report | package: context.package, seeds: context.seeds}
          {:cont, {context, report}}

        :error ->
          {:halt, {context, %{report | status: :failed}}}
      end
    end)
    |> elem(1)
  end

  defp finalize(root, path, report) do
    # Include the evidence file itself in the final status comparison.
    Report.write!(path, %{report | finished_at: timestamp()})

    report =
      case Command.run(root, "git", @status_args) do
        {:ok, result} ->
          unchanged? = report.repository.before == result.output
          status = if unchanged?, do: report.status, else: :failed

          %{
            report
            | status: status,
              repository: %{
                before: report.repository.before,
                after: result.output,
                unchanged?: unchanged?
              }
          }

        {:error, result} ->
          %{
            report
            | status: :failed,
              stages:
                report.stages ++ [entry(:repository_status, :failed, result, result.duration_ms)],
              repository: %{
                before: report.repository.before,
                after: result.output,
                unchanged?: false
              }
          }
      end

    report = %{report | finished_at: timestamp()}
    Report.write!(path, report)
    if report.status == :passed, do: {:ok, report}, else: {:error, report}
  end

  defp entry(name, status, result, duration),
    do: %{name: name, status: status, duration_ms: duration, result: result}

  defp timestamp, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
