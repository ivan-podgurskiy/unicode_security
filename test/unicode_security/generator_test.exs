defmodule UnicodeSecurity.GeneratorTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias UnicodeSecurity.Data.Normalization
  alias UnicodeSecurity.UnicodeData.Generator
  alias UnicodeSecurity.UnicodeData.Source

  test "generates deterministic compilable normalization tables" do
    root = temporary_directory()
    source_directory = Path.join(root, "sources")
    first_output = Path.join(root, "first")
    second_output = Path.join(root, "second")

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

    write_lock!(root, source_directory)

    first_path = Generator.generate!(source_directory, first_output)
    second_path = Generator.generate!(source_directory, second_output)
    first_contents = File.read!(first_path)

    assert first_contents == File.read!(second_path)
    assert String.ends_with?(first_contents, "\n")
    refute first_contents =~ source_directory
    refute first_contents =~ ~r/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/

    capture_io(:stderr, fn ->
      assert [{Normalization, _bytecode}] = Code.compile_file(first_path)
    end)

    assert Normalization.decomposition(0x00C0) == [0x0041, 0x0300]
    assert Normalization.decomposition(0x00A0) == nil
    assert Normalization.decomposition(0x1200) == [0x0041, 0x0300]
    assert Normalization.combining_class(0x0300) == 230
    assert Normalization.combining_class(0x0315) == 232
    assert Normalization.combining_class(0x0041) == 0
  end

  defp write_lock!(root, source_directory) do
    declarations =
      Enum.filter(
        Source.sources(),
        &(&1.name in ["UnicodeData.txt", "DerivedCombiningClass.txt"])
      )

    lock = Source.lock!(declarations, source_directory)
    contents = inspect(lock, pretty: true, limit: :infinity, printable_limit: :infinity)

    File.write!(Path.join(root, "sources.lock"), contents <> "\n")
  end

  defp temporary_directory do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    directory = Path.join(System.tmp_dir!(), "unicode-security-generator-#{suffix}")

    on_exit(fn -> File.rm_rf!(directory) end)
    directory
  end
end
