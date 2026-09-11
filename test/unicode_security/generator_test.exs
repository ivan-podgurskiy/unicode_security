defmodule UnicodeSecurity.GeneratorTest do
  use ExUnit.Case, async: false

  alias UnicodeSecurity.Data.Normalization
  alias UnicodeSecurity.UnicodeData.Generator
  alias UnicodeSecurity.UnicodeData.Source

  # Catches nonportable provenance, omitted sources, and nondeterministic generation.
  test "generates deterministic literal manifest from all declarations and locked bytes" do
    root = temporary_directory()
    source_directory = write_sources!(root)
    first_path = Generator.generate_manifest!(source_directory, Path.join(root, "first"))
    second_path = Generator.generate_manifest!(source_directory, Path.join(root, "second"))
    contents = File.read!(first_path)

    assert contents == File.read!(second_path)
    assert String.ends_with?(contents, "\n")
    refute contents =~ root

    {lock, []} = Code.eval_file(Path.join(root, "sources.lock"))

    expected = %{
      release_status: :draft,
      sources:
        Source.sources()
        |> Enum.sort_by(& &1.name)
        |> Enum.map(&Map.merge(&1, Map.fetch!(lock, &1.name)))
    }

    verification = """
    [{UnicodeSecurity.Data.Manifest, _}] = Code.compile_file(#{inspect(first_path)})
    expected = #{inspect(expected, limit: :infinity)}
    true = UnicodeSecurity.Data.Manifest.get() == expected
    """

    elixir = System.find_executable("elixir") || raise "elixir executable not found"
    assert {"", 0} = System.cmd(elixir, ["-e", verification], stderr_to_stdout: true)
  end

  test "refuses manifest generation when a conformance-only source changes" do
    root = temporary_directory()
    source_directory = write_sources!(root)
    File.write!(Path.join(source_directory, "NormalizationTest.txt"), "tampered\n")

    assert_raise ArgumentError, ~r/byte-size mismatch for NormalizationTest.txt/, fn ->
      Generator.generate_manifest!(source_directory, Path.join(root, "output"))
    end

    refute File.exists?(Path.join(root, "output/manifest.ex"))
  end

  test "offline checker accepts reproduced modules and rejects drift in each output" do
    root = checker_project!()
    assert {"", 0} = run_check(root, "check_generated.exs")

    for name <- ["normalization.ex", "confusables.ex", "manifest.ex"] do
      path = Path.join(root, "lib/unicode_security/data/#{name}")
      original = File.read!(path)
      File.write!(path, original <> "# drift\n")
      {output, status} = run_check(root, "check_generated.exs")
      assert status != 0
      assert output =~ "generated data mismatch: #{name}"
      assert File.read!(path) == original <> "# drift\n"
      File.write!(path, original)
    end
  end

  # Catches the normal entrypoint writing tables before validating later locked sources.
  test "generation entrypoint preserves every output when any locked source is invalid" do
    root = checker_project!()
    script = Path.join(root, "scripts/generate_unicode_data.exs")
    File.cp!("scripts/generate_unicode_data.exs", script)

    originals =
      Map.new(["normalization.ex", "confusables.ex", "manifest.ex"], fn name ->
        path = Path.join(root, "lib/unicode_security/data/#{name}")
        contents = File.read!(path) <> "# existing output to preserve\n"
        File.write!(path, contents)
        {path, contents}
      end)

    elixir = System.find_executable("elixir") || raise "elixir executable not found"
    beam_directory = Generator |> :code.which() |> List.to_string() |> Path.dirname()
    invocation = "Mix.start(); Code.require_file(#{inspect(script)})"

    for source <- Source.sources() do
      source_path = Path.join(root, "priv/unicode/18.0.0-draft/#{source.name}")
      original_source = File.read!(source_path)
      File.write!(source_path, original_source <> "# tampered\n")

      {output, status} =
        System.cmd(elixir, ["-pa", beam_directory, "-e", invocation],
          cd: root,
          stderr_to_stdout: true
        )

      assert status != 0
      assert output =~ "byte-size mismatch for #{source.name}"

      for {path, contents} <- originals do
        assert File.read!(path) == contents,
               "#{Path.basename(path)} was rewritten despite invalid #{source.name}"
      end

      refute output =~ "generated lib/"
      File.write!(source_path, original_source)
    end
  end

  test "offline checker verifies all locked sources before accepting generated files" do
    root = checker_project!()
    File.write!(Path.join(root, "priv/unicode/18.0.0-draft/NormalizationTest.txt"), "tampered\n")

    {output, status} = run_check(root, "check_generated.exs")
    assert status != 0
    assert output =~ "byte-size mismatch for NormalizationTest.txt"
  end

  test "release gate reports the intentional draft block and checks generated data first" do
    root = checker_project!()

    assert {"release blocked: Unicode 18.0.0 data status is draft\n", 1} =
             run_check(root, "check_release_data.exs")

    File.write!(Path.join(root, "lib/unicode_security/data/manifest.ex"), "# stale\n")
    {output, status} = run_check(root, "check_release_data.exs")
    assert status != 0
    assert output =~ "generated data mismatch: manifest.ex"
    refute output =~ "release blocked:"
  end

  # Catches unsorted packed indices, dropped multi-scalar values, misses, and nondeterminism.
  test "generates deterministic confusable mappings with working packed lookups" do
    root = temporary_directory()
    source_directory = write_sources!(root)
    first_path = Generator.generate_confusables!(source_directory, Path.join(root, "first"))
    second_path = Generator.generate_confusables!(source_directory, Path.join(root, "second"))

    assert File.read!(first_path) == File.read!(second_path)

    verification = """
    [{UnicodeSecurity.Data.Confusables, _}] = Code.compile_file(#{inspect(first_path)})
    nil = UnicodeSecurity.Data.Confusables.mapping(0)
    nil = UnicodeSecurity.Data.Confusables.mapping(0x006E)
    nil = UnicodeSecurity.Data.Confusables.mapping(0x10FFFF)
    [0x0072, 0x006E] = UnicodeSecurity.Data.Confusables.mapping(0x006D)
    [0x0061] = UnicodeSecurity.Data.Confusables.mapping(0x0430)
    [0x0041, 0x0300] = UnicodeSecurity.Data.Confusables.mapping(0x1200)
    """

    elixir = System.find_executable("elixir") || raise "elixir executable not found"
    assert {"", 0} = System.cmd(elixir, ["-e", verification], stderr_to_stdout: true)
  end

  test "refuses confusable generation when the locked source changes" do
    root = temporary_directory()
    source_directory = write_sources!(root)
    File.write!(Path.join(source_directory, "confusables.txt"), "0430 ; 0062 ; MA\n")

    assert_raise ArgumentError, fn ->
      Generator.generate_confusables!(source_directory, Path.join(root, "output"))
    end

    refute File.exists?(Path.join(root, "output/confusables.ex"))
  end

  test "generates deterministic normalization tables" do
    root = temporary_directory()
    source_directory = write_sources!(root)
    first_output = Path.join(root, "first")
    second_output = Path.join(root, "second")

    first_path = Generator.generate!(source_directory, first_output)
    second_path = Generator.generate!(source_directory, second_output)
    first_contents = File.read!(first_path)

    assert first_contents == File.read!(second_path)
    assert String.ends_with?(first_contents, "\n")
    refute first_contents =~ source_directory
    refute first_contents =~ ~r/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/
  end

  test "compiles fixture tables without replacing the loaded normalization module" do
    root = temporary_directory()
    source_directory = write_sources!(root)
    generated_path = Generator.generate!(source_directory, Path.join(root, "compiled"))

    assert Normalization.decomposition(0x1200) == nil

    verification = """
    [{UnicodeSecurity.Data.Normalization, _bytecode}] = Code.compile_file(#{inspect(generated_path)})
    [0x0041, 0x0300] = UnicodeSecurity.Data.Normalization.decomposition(0x00C0)
    nil = UnicodeSecurity.Data.Normalization.decomposition(0x00A0)
    [0x0041, 0x0300] = UnicodeSecurity.Data.Normalization.decomposition(0x1200)
    230 = UnicodeSecurity.Data.Normalization.combining_class(0x0300)
    232 = UnicodeSecurity.Data.Normalization.combining_class(0x0315)
    0 = UnicodeSecurity.Data.Normalization.combining_class(0x0041)
    """

    elixir = System.find_executable("elixir") || raise "elixir executable not found"
    assert {"", 0} = System.cmd(elixir, ["-e", verification], stderr_to_stdout: true)

    assert Normalization.decomposition(0x1200) == nil
  end

  defp write_sources!(root) do
    source_directory = Path.join(root, "sources")
    File.mkdir_p!(source_directory)

    additional_mappings =
      Enum.map_join(0x1000..0x1200, fn codepoint ->
        code = codepoint |> Integer.to_string(16) |> String.upcase()
        "#{code};TEST CHARACTER;Lo;0;L;0041 0300;;;;N;;;;;\n"
      end)

    File.write!(
      Path.join(source_directory, "UnicodeData.txt"),
      "00C0;LATIN CAPITAL LETTER A WITH GRAVE;Lu;0;L;0041 0300;;;;N;;;;00E0;\n" <>
        "00A0;NO-BREAK SPACE;Zs;0;CS;<noBreak> 0020;;;;N;;;;;\n" <>
        additional_mappings
    )

    File.write!(
      Path.join(source_directory, "DerivedCombiningClass.txt"),
      "0000..02FF ; 0 # default\n0300..0314 ; 230 # Mn\n0315 ; 232 # Mn\n"
    )

    File.write!(
      Path.join(source_directory, "confusables.txt"),
      "1200 ; 0041 0300 ; MA\n0430 ; 0061 ; MA\n006D ; 0072 006E ; MA\n"
    )

    File.write!(Path.join(source_directory, "NormalizationTest.txt"), "# fixture\n")

    write_lock!(root, source_directory)
    source_directory
  end

  defp write_lock!(root, source_directory) do
    lock = Source.lock!(Source.sources(), source_directory)
    contents = inspect(lock, pretty: true, limit: :infinity, printable_limit: :infinity)

    File.write!(Path.join(root, "sources.lock"), contents <> "\n")
  end

  defp checker_project! do
    root = temporary_directory()
    File.mkdir_p!(Path.join(root, "scripts"))

    for script <- ["check_generated.exs", "check_release_data.exs"] do
      assert File.regular?(Path.join("scripts", script)), "missing #{script}"
      File.cp!(Path.join("scripts", script), Path.join(root, "scripts/#{script}"))
    end

    fixture = write_sources!(Path.join(root, "priv/unicode"))
    source_directory = Path.join(root, "priv/unicode/18.0.0-draft")
    File.rename!(fixture, source_directory)
    output_directory = Path.join(root, "lib/unicode_security/data")
    Generator.generate!(source_directory, output_directory)
    Generator.generate_confusables!(source_directory, output_directory)
    Generator.generate_manifest!(source_directory, output_directory)
    root
  end

  defp run_check(root, script) do
    elixir = System.find_executable("elixir") || raise "elixir executable not found"
    beam_directory = Generator |> :code.which() |> List.to_string() |> Path.dirname()

    System.cmd(elixir, ["-pa", beam_directory, Path.join(root, "scripts/#{script}")],
      cd: root,
      stderr_to_stdout: true
    )
  end

  defp temporary_directory do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    directory = Path.join(System.tmp_dir!(), "unicode-security-generator-#{suffix}")

    on_exit(fn -> File.rm_rf!(directory) end)
    directory
  end
end
