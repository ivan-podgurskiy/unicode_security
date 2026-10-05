alias UnicodeSecurity.UnicodeData.Source

{:ok, _applications} = Application.ensure_all_started(:inets)
{:ok, _applications} = Application.ensure_all_started(:ssl)

project_root = Path.expand("..", __DIR__)
directory = Source.directory(project_root)
lock_path = Path.join(project_root, "priv/unicode/sources.lock")
sources = Source.sources()

mode =
  case System.argv() do
    [] -> :locked
    ["--create-lock"] -> :create_lock
    ["--update-lock"] -> :update_lock
    _ -> raise ArgumentError, "use no arguments, --create-lock, or --update-lock"
  end

if mode == :create_lock and File.exists?(lock_path) do
  raise ArgumentError, "sources.lock already exists; deliberate changes require --update-lock"
end

if mode == :locked and not File.regular?(lock_path) do
  raise ArgumentError, "sources.lock is missing; initial acquisition requires --create-lock"
end

lock =
  if mode == :locked do
    {existing_lock, _binding} = Code.eval_file(lock_path)

    if File.dir?(directory) do
      :ok = Source.verify!(sources, directory, existing_lock)
    else
      Source.fetch!(sources, directory)
    end

    existing_lock
  else
    Source.fetch!(sources, directory, :update_lock)
  end

Enum.each(sources, fn %{name: name, url: url} ->
  %{bytes: bytes, sha256: sha256} = Map.fetch!(lock, name)
  Mix.shell().info("#{name}: #{bytes} bytes #{sha256} #{url}")
end)
