defmodule UnicodeSecurity.ReleaseCandidate.Report do
  @moduledoc """
  Writes deterministic release evidence using a completed temporary sibling.

  A successful read observes complete report bytes. Replacement is atomic for
  callers using the same Erlang file server. On Windows, an external process or
  raw-file reader may briefly receive `:enoent` while an existing destination is
  replaced; uninterrupted external visibility is not guaranteed by OTP.
  """

  @spec write!(Path.t(), map()) :: :ok
  def write!(path, report) do
    File.mkdir_p!(Path.dirname(path))
    temporary = path <> ".#{System.unique_integer([:positive, :monotonic])}.tmp"
    bytes = :erlang.term_to_binary(report, [:deterministic])

    # Establish ownership before installing cleanup. An exclusive-open failure
    # must leave another writer's file intact.
    file = File.open!(temporary, [:write, :binary, :exclusive])

    try do
      case IO.binwrite(file, bytes) do
        :ok ->
          :ok

        {:error, reason} ->
          raise File.Error, reason: reason, action: "write to file", path: temporary
      end

      :ok = File.close(file)
      File.rename!(temporary, path)
    after
      File.close(file)
      File.rm(temporary)
    end

    :ok
  end
end
