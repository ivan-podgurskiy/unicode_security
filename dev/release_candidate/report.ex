defmodule UnicodeSecurity.ReleaseCandidate.Report do
  @moduledoc false

  @spec write!(Path.t(), map()) :: :ok
  def write!(path, report) do
    File.mkdir_p!(Path.dirname(path))
    temporary = path <> ".#{System.unique_integer([:positive, :monotonic])}.tmp"

    try do
      File.write!(temporary, :erlang.term_to_binary(report, [:deterministic]), [
        :binary,
        :exclusive
      ])

      File.rename!(temporary, path)
    after
      File.rm(temporary)
    end

    :ok
  end
end
