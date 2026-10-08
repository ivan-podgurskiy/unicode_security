defmodule UnicodeSecurity.Test.ElixirRunner do
  @moduledoc false

  # Windows elixir.bat cannot safely receive multiline -e arguments. A script
  # also keeps embedded quotes/newlines intact. Spaces exercise path quoting.
  def run(source, options \\ []) do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    directory = Path.join(System.tmp_dir!(), "unicode security verifier #{suffix}")
    File.mkdir!(directory)
    path = Path.join(directory, "verification.exs")
    {elixir_args, options} = Keyword.pop(options, :elixir_args, [])
    {paths, command_options} = Keyword.pop(options, :paths, [])
    arguments = elixir_args ++ Enum.flat_map(paths, &["-pa", &1]) ++ [path]
    executable = System.find_executable("elixir") || raise "elixir executable not found"

    try do
      File.write!(path, source, [:binary, :exclusive])
      System.cmd(executable, arguments, Keyword.put(command_options, :stderr_to_stdout, true))
    after
      File.rm_rf!(directory)
    end
  end
end
