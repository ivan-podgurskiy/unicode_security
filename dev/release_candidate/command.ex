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
          command_opts = [cd: root, env: Keyword.get(opts, :env, []), stderr_to_stdout: true]

          case Keyword.fetch(opts, :cmd) do
            {:ok, cmd} -> cmd.(path, args, command_opts)
            :error -> invoke(path, args, command_opts)
          end
      end

    result = %{
      argv: [executable | args],
      output: output,
      status: status,
      duration_ms: System.monotonic_time(:millisecond) - started
    }

    if status == 0, do: {:ok, result}, else: {:error, result}
  end

  # Windows mix.bat keeps the Erlang port open. The extensionless mix script
  # next to it returns when invoked through elixir.bat, which System.cmd can reap.
  @doc false
  @spec script_launch(binary(), [binary()], {:unix | :win32, atom()}, binary() | nil) ::
          {binary(), [binary()]}
  def script_launch(path, args, os_type, elixir) do
    normalized = String.replace(path, "\\", "/")
    script = Path.join(Path.dirname(normalized), "mix")

    if match?({:win32, _}, os_type) and mix_batch?(normalized) and is_binary(elixir) and
         File.regular?(script) do
      {elixir, [script | args]}
    else
      {path, args}
    end
  end

  defp invoke(path, args, opts) do
    {command, args} = script_launch(path, args, :os.type(), System.find_executable("elixir"))
    System.cmd(command, args, opts)
  end

  defp mix_batch?(path) do
    String.downcase(Path.basename(path)) == "mix.bat"
  end
end
