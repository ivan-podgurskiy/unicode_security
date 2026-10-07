defmodule UnicodeSecurity.ReleaseCandidate.Command do
  @moduledoc false

  @spec run(binary(), binary(), [binary()], keyword()) :: {:ok, map()} | {:error, map()}
  def run(root, executable, args, opts \\ []) do
    started = System.monotonic_time(:millisecond)

    {output, status} =
      case System.find_executable(executable) do
        nil ->
          {"Executable not found: #{executable}", 127}

        path ->
          cmd = Keyword.get(opts, :cmd, &System.cmd/3)
          cmd.(path, args, cd: root, env: Keyword.get(opts, :env, []), stderr_to_stdout: true)
      end

    result = %{
      argv: [executable | args],
      output: output,
      status: status,
      duration_ms: System.monotonic_time(:millisecond) - started
    }

    if status == 0, do: {:ok, result}, else: {:error, result}
  end
end
