defmodule UnicodeSecurity.ScriptsTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Data.Scripts, as: Data
  alias UnicodeSecurity.InvalidInputError
  alias UnicodeSecurity.Scripts
  alias UnicodeSecurity.Test.ElixirRunner
  alias UnicodeSecurity.UnicodeData.ScriptParser

  @aliases "# PropertyValueAliases-18.0.0.txt\nsc ; Latn ; Latin\nsc ; Cyrl ; Cyrillic\nsc ; Zzzz ; Unknown\nsc ; Zinh ; Inherited ; Qaai\n"
  @scripts "# Scripts-18.0.0.txt\n# @missing: 0000..10FFFF; Unknown\n"
  @extensions "# ScriptExtensions-18.0.0.txt\n# @missing: 0000..10FFFF; <script>\n"

  test "recognizes every canonical script name from the independently read pinned aliases" do
    Code.ensure_loaded!(Data)

    expected_names =
      reference_lines("PropertyValueAliases.txt")
      |> Enum.flat_map(fn
        ["sc", _short, long | _other] -> [String.downcase(long)]
        _ -> []
      end)
      |> Enum.sort()

    # Only existing atoms from the compiled table are used; never create atoms.
    for name <- expected_names do
      assert Data.known_script?(String.to_existing_atom(name))
    end
  end

  @tag timeout: 120_000
  test "matches every scalar, range boundary and default in independently read pinned properties" do
    aliases =
      reference_lines("PropertyValueAliases.txt")
      |> Enum.reduce(%{}, fn
        ["sc", short, long | other], acc ->
          Enum.reduce([short, long | other], acc, &Map.put(&2, &1, String.downcase(long)))

        _, acc ->
          acc
      end)

    scripts = reference_property("Scripts.txt", &Map.fetch!(aliases, &1))

    extensions =
      reference_property("ScriptExtensions.txt", fn value ->
        value |> String.split() |> Enum.map(&Map.fetch!(aliases, &1)) |> Enum.sort()
      end)

    for code <- 0..0x10FFFF, code not in 0xD800..0xDFFF do
      expected = Map.get(scripts, code, "unknown")

      assert Atom.to_string(Data.script(code)) == expected,
             "Script U+#{Integer.to_string(code, 16)}"

      assert Enum.map(Data.extensions(code), &Atom.to_string/1) ==
               Map.get(extensions, code, [expected]),
             "Script_Extensions U+#{Integer.to_string(code, 16)}"
    end
  end

  test "script APIs operate with only compiled runtime modules and no source tree" do
    beam_directory = Application.app_dir(:unicode_security, "ebin")

    loader =
      Enum.map_join(
        [UnicodeSecurity, UnicodeSecurity.Scripts, Data, UnicodeSecurity.Utf8, InvalidInputError],
        "\n",
        fn module ->
          path = Path.join(beam_directory, Atom.to_string(module))
          ":code.load_abs(String.to_charlist(#{inspect(path)}))"
        end
      )

    verification = """
    [:cyrillic, :latin] = UnicodeSecurity.scripts("раypal")
    false = UnicodeSecurity.mixed_script?("ねガ")
    false = UnicodeSecurity.mixed_script?("漢a")
    true = UnicodeSecurity.mixed_script?("aー")
    false = Code.ensure_loaded?(UnicodeSecurity.UnicodeData.ScriptParser)
    """

    assert {"", 0} = ElixirRunner.run(loader <> "\n" <> verification, cd: System.tmp_dir!())
  end

  test "reports ordinary Script properties without losing neutral or unknown values" do
    assert UnicodeSecurity.scripts("раypal") == [:cyrillic, :latin]
    assert UnicodeSecurity.scripts("a \u0301") == [:common, :inherited, :latin]
    assert UnicodeSecurity.scripts("ねガ") == [:hiragana, :katakana]
    assert UnicodeSecurity.scripts("\u0378\u{10FFFF}\uE000") == [:unknown]
    assert UnicodeSecurity.scripts("") == []
    assert UnicodeSecurity.scripts(:binary.copy("a", 4096)) == [:latin]
  end

  test "uses revision 34 augmented Script_Extensions intersection" do
    for input <- [
          "",
          " 123!",
          "\u034F",
          "Circle",
          "СігсӀе",
          "Circ1e",
          "〆切",
          "ねガ",
          "漢a",
          "漢ㄅ",
          "漢한",
          "あー",
          "カー",
          "\u0378"
        ] do
      refute UnicodeSecurity.mixed_script?(input), inspect(input)
    end

    for input <- ["раypal", "Сirсlе", "aー", "あ한", "a\u0378", "漢ㄅa"] do
      assert UnicodeSecurity.mixed_script?(input), inspect(input)
    end

    assert Scripts.resolved_set([]) == :all
    assert Scripts.resolved_set([0x20, 0x034F]) == :all
    assert Scripts.resolved_set([?a]) == MapSet.new([:latin, :hntl])
    assert Scripts.resolved_set([0x306D, 0x30AC]) == MapSet.new([:jpan])

    assert Scripts.resolved_set([0x3006, 0x5207]) ==
             MapSet.new([:han, :hanb, :hntl, :jpan, :kore])
  end

  test "looks up extension overrides and uses Script fallback" do
    assert Data.script(?a) == :latin
    assert Data.extensions(?a) == [:latin]
    assert Data.script(0x30FC) == :common
    assert Data.extensions(0x30FC) == [:hiragana, :katakana]
    assert Data.extensions(0x0378) == [:unknown]
    assert Data.extensions(0x20) == [:common]
    assert Data.extensions(0x034F) == [:inherited]
  end

  test "validates the complete original input and retains decoder error offsets" do
    for api <- [&UnicodeSecurity.scripts/1, &UnicodeSecurity.mixed_script?/1] do
      for input <- [nil, 42, [97, 98, 99]] do
        assert_raise ArgumentError, fn -> api.(input) end
      end

      for {input, reason, offset} <- [
            {"аa" <> <<0xFF>>, :invalid_utf8, 3},
            {"é" <> <<0xED, 0xA0, 0x80>>, :invalid_utf8, 2},
            {:binary.copy("a", 4097), :input_too_long, 4096}
          ] do
        error = assert_raise InvalidInputError, fn -> api.(input) end
        assert {error.reason, error.byte_offset} == {reason, offset}
      end
    end
  end

  test "parses script aliases including historical aliases and sorted ranges" do
    aliases = ScriptParser.aliases!(@aliases <> "gc; Lu; Uppercase_Letter\n")
    assert aliases["Qaai"] == "inherited"
    assert aliases["Latin"] == "latin"
    refute Map.has_key?(aliases, "Lu")

    assert ScriptParser.scripts!(@scripts <> "0062; Latin\n0041; Latn\n", aliases) ==
             [{0x41, 0x41, "latin"}, {0x62, 0x62, "latin"}]

    assert ScriptParser.extensions!(@extensions <> "0300..0301; Latn Cyrl\n", aliases) ==
             [{0x300, 0x301, ["cyrillic", "latin"]}]
  end

  test "rejects malformed aliases, duplicate aliases and missing version evidence" do
    for input <- [
          "",
          String.replace(@aliases, "18.0.0", "17.0.0"),
          @aliases <> "sc; Latn; Wrong\n",
          @aliases <> "sc; Fake; Latin\n",
          @aliases <> "sc; Xxxx\n",
          @aliases <> "sc; Xxxx; bad-name\n",
          @aliases <> "sc; Xxxx; \n"
        ] do
      assert_raise ArgumentError, fn -> ScriptParser.aliases!(input) end
    end
  end

  test "rejects invalid ranges, unknown values, overlap and malformed defaults" do
    aliases = ScriptParser.aliases!(@aliases)

    for {parser, header} <- [
          {&ScriptParser.scripts!/2, @scripts},
          {&ScriptParser.extensions!/2, @extensions}
        ] do
      for body <- [
            "0041; Nope",
            "0041",
            "0041; Latn; extra",
            "ZZZZ; Latn",
            "0042..0041; Latn",
            "110000; Latn",
            "D800; Latn",
            "D7FF..E000; Latn",
            "0041..0042; Latn\n0042; Cyrl",
            "0041; Latn\n0041; Latn",
            "0041; "
          ] do
        assert_raise ArgumentError, fn -> parser.(header <> body, aliases) end
      end

      for input <- [
            "",
            String.replace(header, "18.0.0", "17.0.0"),
            String.replace(header, "0000..10FFFF", "0000..FFFF"),
            header <> "# @missing: 0000..10FFFF; Wrong\n"
          ] do
        assert_raise ArgumentError, fn -> parser.(input, aliases) end
      end
    end

    for values <- ["Latn Latn", "Latn Latin", "Latn Zinh"] do
      assert_raise ArgumentError, fn ->
        ScriptParser.extensions!(@extensions <> "0041; #{values}", aliases)
      end
    end
  end

  defp reference_lines(name) do
    Path.join("priv/unicode/18.0.0-draft", name)
    |> File.stream!()
    |> Stream.map(fn line -> line |> String.split("#", parts: 2) |> hd() |> String.trim() end)
    |> Stream.reject(&(&1 == ""))
    |> Enum.map(fn line -> line |> String.split(";") |> Enum.map(&String.trim/1) end)
  end

  defp reference_property(name, transform) do
    Enum.reduce(reference_lines(name), %{}, fn [range, value], acc ->
      bounds = range |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))
      value = transform.(value)
      Enum.reduce(hd(bounds)..List.last(bounds), acc, &Map.put(&2, &1, value))
    end)
  end
end
