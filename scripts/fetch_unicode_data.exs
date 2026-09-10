alias UnicodeSecurity.UnicodeData.Source

{:ok, _applications} = Application.ensure_all_started(:inets)
{:ok, _applications} = Application.ensure_all_started(:ssl)

project_root = Path.expand("..", __DIR__)
directory = Path.join(project_root, "priv/unicode/18.0.0-draft")
lock_path = Path.join(project_root, "priv/unicode/sources.lock")
sources = Source.sources()

lock =
  if File.dir?(directory) and File.regular?(lock_path) do
    {existing_lock, _binding} = Code.eval_file(lock_path)
    :ok = Source.verify!(sources, directory, existing_lock)
    existing_lock
  else
    acquired_lock = Source.fetch!(sources, directory)

    lock_contents =
      inspect(acquired_lock, pretty: true, limit: :infinity, printable_limit: :infinity)

    temporary_lock = "#{lock_path}.tmp-#{System.unique_integer([:positive, :monotonic])}"

    File.mkdir_p!(Path.dirname(lock_path))

    try do
      File.write!(temporary_lock, lock_contents <> "\n", [:binary, :exclusive])
      File.rename!(temporary_lock, lock_path)
    after
      if File.exists?(temporary_lock), do: File.rm!(temporary_lock)
    end

    acquired_lock
  end

Enum.each(sources, fn %{name: name, url: url} ->
  %{bytes: bytes, sha256: sha256} = Map.fetch!(lock, name)
  Mix.shell().info("#{name}: #{bytes} bytes #{sha256} #{url}")
end)
