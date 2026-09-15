alias UnicodeSecurity.UnicodeData.Generator

project_root = Path.expand("..", __DIR__)
source_directory = Path.join(project_root, "priv/unicode/18.0.0-draft")
tracked_directory = Path.join(project_root, "lib/unicode_security/data")
suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
temporary_directory = Path.join(System.tmp_dir!(), "unicode-security-check-#{suffix}")

try do
  File.mkdir!(temporary_directory)

  try do
    # Manifest generation verifies the complete source lock before parsing any tables.
    paths = [
      Generator.generate_manifest!(source_directory, temporary_directory),
      Generator.generate!(source_directory, temporary_directory),
      Generator.generate_confusables!(source_directory, temporary_directory),
      Generator.generate_bidi!(source_directory, temporary_directory),
      Generator.generate_scripts!(source_directory, temporary_directory)
    ]

    Enum.each(paths, fn generated_path ->
      name = Path.basename(generated_path)
      expected = File.read!(generated_path)

      unless File.read(Path.join(tracked_directory, name)) == {:ok, expected} do
        raise "generated data mismatch: #{name}"
      end
    end)
  after
    File.rm_rf!(temporary_directory)
  end
rescue
  error ->
    IO.puts(:stderr, Exception.message(error))
    System.halt(1)
end
