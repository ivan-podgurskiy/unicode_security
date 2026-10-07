alias UnicodeSecurity.ReleaseCandidate

opts =
  case System.argv() do
    [] ->
      []

    ["--report", path] when path != "" ->
      if String.starts_with?(path, "-") do
        IO.puts(:stderr, "usage: mix rc [--report PATH]")
        System.halt(1)
      end

      [report_path: path]

    _ ->
      IO.puts(:stderr, "usage: mix rc [--report PATH]")
      System.halt(1)
  end

{outcome, report} = ReleaseCandidate.run(opts)

for stage <- report.stages do
  IO.puts("#{stage.name}: #{stage.status} (#{stage.duration_ms} ms)")

  if stage.status == :failed do
    IO.puts("command: #{inspect(Map.get(stage.result, :argv, []))}")
    IO.puts(Map.get(stage.result, :output, inspect(stage.result)))
  end
end

if report.stages == [] and report.repository.before != "" do
  IO.puts("preflight: failed; repository is dirty\n#{report.repository.before}")
end

IO.puts("release candidate #{report.version} at #{report.commit}: #{report.status}")
IO.puts("repository unchanged: #{report.repository.unchanged?}")

case report.package do
  nil -> IO.puts("package: unavailable")
  package -> IO.puts("package: #{package.bytes} bytes; SHA-256 #{package.sha256}")
end

System.halt(if outcome == :ok, do: 0, else: 1)
