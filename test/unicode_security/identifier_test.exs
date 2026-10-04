defmodule UnicodeSecurity.IdentifierTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Data.Identifier, as: Data
  alias UnicodeSecurity.Identifier
  alias UnicodeSecurity.InvalidInputError
  alias UnicodeSecurity.Normalization
  alias UnicodeSecurity.Test.ElixirRunner
  alias UnicodeSecurity.UnicodeData.IdentifierParser
  alias UnicodeSecurity.UnicodeData.Source

  @status "# IdentifierStatus.txt\n# Version: 18.0.0\n# @missing: 0000..10FFFF; Restricted\n"
  @types "# IdentifierType.txt\n# Version: 18.0.0\n# @missing: 0000..10FFFF; Not_Character\n"

  @tag timeout: 120_000
  test "matches every scalar, range boundary and default in independently read pinned properties" do
    statuses = reference_property("IdentifierStatus.txt")
    types = reference_property("IdentifierType.txt")

    for code <- 0..0x10FFFF, code not in 0xD800..0xDFFF do
      assert Data.status(code) |> Atom.to_string() |> String.capitalize() ==
               Map.get(statuses, code, "Restricted"),
             "Identifier_Status U+#{Integer.to_string(code, 16)}"

      assert Enum.map(Data.types(code), &Atom.to_string/1) ==
               types
               |> Map.get(code, "Not_Character")
               |> String.split()
               |> Enum.map(&String.downcase/1)
               |> Enum.sort(),
             "Identifier_Type U+#{Integer.to_string(code, 16)}"
    end
  end

  test "reports exact pinned scalar status and sorted type sets" do
    assert UnicodeSecurity.identifier_status(?a) == :allowed
    assert UnicodeSecurity.identifier_types(?a) == [:recommended]
    assert UnicodeSecurity.identifier_status(0x200D) == :restricted
    assert UnicodeSecurity.identifier_types(0x200D) == [:default_ignorable]
    assert UnicodeSecurity.identifier_status(0x018D) == :restricted
    assert UnicodeSecurity.identifier_types(0x018D) == [:obsolete, :technical]
    assert UnicodeSecurity.identifier_status(0x0378) == :restricted
    assert UnicodeSecurity.identifier_types(0x0378) == [:not_character]
  end

  test "accepts only strings whose identifier-status predicate succeeds" do
    assert UnicodeSecurity.allowed_identifier?("paypal")
    assert UnicodeSecurity.allowed_identifier?("")
    assert UnicodeSecurity.allowed_identifier?(:binary.copy("a", 4096))
    refute UnicodeSecurity.allowed_identifier?("pay\u200Dpal")
  end

  test "applies canonical closure where original-only, NFD-only and their union fail" do
    composed = "\u0622\u0115"
    decomposed = "\u0627\u0653e\u0306"

    refute Enum.all?([0x0622, 0x0115], &(Data.status(&1) == :allowed))
    refute decomposed |> String.to_charlist() |> Enum.all?(&(Data.status(&1) == :allowed))
    assert UnicodeSecurity.allowed_identifier?(composed)
    assert UnicodeSecurity.allowed_identifier?(decomposed)
    assert Identifier.allowed_scalars?([0x0622, 0x0115])
  end

  @tag timeout: 120_000
  test "accepts every Allowed scalar and its canonical decomposition" do
    allowed = reference_property("IdentifierStatus.txt") |> Map.keys()

    for code <- allowed do
      scalar = <<code::utf8>>

      assert UnicodeSecurity.allowed_identifier?(scalar),
             "original U+#{Integer.to_string(code, 16)}"

      assert scalar |> Normalization.nfd() |> UnicodeSecurity.allowed_identifier?(),
             "NFD of U+#{Integer.to_string(code, 16)}"
    end
  end

  @tag timeout: 120_000
  test "accepts every Restricted scalar whose full NFD is entirely Allowed" do
    rescued =
      (canonical_decomposition_scalars() ++ Enum.to_list(0xAC00..0xD7A3))
      |> Enum.uniq()
      |> Enum.filter(fn code ->
        nfd = Normalization.nfd_scalars([code])
        Data.status(code) == :restricted and Enum.all?(nfd, &(Data.status(&1) == :allowed))
      end)

    assert rescued != []

    for code <- rescued do
      assert UnicodeSecurity.allowed_identifier?(<<code::utf8>>),
             "canonically Allowed U+#{Integer.to_string(code, 16)}"
    end
  end

  test "packed rescue mappings exactly cover supported explicit canonical shapes" do
    expected = explicit_rescues()

    allowed_marks =
      reference_property("IdentifierStatus.txt")
      |> Map.keys()
      |> Enum.group_by(&UnicodeSecurity.Data.Normalization.combining_class/1)
      |> Map.delete(0)
      |> Enum.map(fn {class, marks} -> {class, Enum.min(marks)} end)

    assert expected != %{}
    assert Enum.all?(expected, fn {_starter, candidates} -> length(candidates) <= 8 end)

    Enum.each(expected, fn {starter, candidates} ->
      assert Data.rescues(starter) == candidates

      Enum.each(candidates, fn candidate ->
        classes = Enum.map(candidate, &UnicodeSecurity.Data.Normalization.combining_class/1)

        assert hd(classes) == 0
        assert Enum.all?(tl(classes), &(&1 > 0)) or classes in [[0, 0], [0, 0, 0]]
        assert Identifier.allowed_scalars?(candidate)

        # Appending an Allowed mark to the all-Allowed rescue witness must remain
        # accepted even when NFD reorders it before, within or after rescue marks.
        for {_class, mark} <- allowed_marks do
          assert Identifier.allowed_scalars?(candidate ++ [mark])
        end
      end)
    end)
  end

  test "handles rescue marks by CCC group prefixes without crossing equal classes" do
    assert UnicodeSecurity.allowed_identifier?("d\u0327\u032D")
    assert UnicodeSecurity.allowed_identifier?("d\u032D\u0323")
    refute UnicodeSecurity.allowed_identifier?("d\u0323\u032D")
    assert UnicodeSecurity.allowed_identifier?("d\u032D\u0301")
    refute UnicodeSecurity.allowed_identifier?("d\u032D\u0653")
    refute UnicodeSecurity.allowed_identifier?("d\u0653")
    refute UnicodeSecurity.allowed_identifier?("d\u0378")

    refute UnicodeSecurity.allowed_identifier?("\u032D")
    refute UnicodeSecurity.allowed_identifier?("\u0653")
    assert UnicodeSecurity.allowed_identifier?("\u0306")
  end

  test "handles algorithmic Hangul and multi-starter explicit rescues" do
    assert UnicodeSecurity.allowed_identifier?("\u1100\u1161")
    assert UnicodeSecurity.allowed_identifier?("\u1100\u1161\u11A8")
    assert UnicodeSecurity.allowed_identifier?("\u1100\u1161\u0323")
    refute UnicodeSecurity.allowed_identifier?("\u1100")
    refute UnicodeSecurity.allowed_identifier?("\u1100\u0323\u1161")
    refute UnicodeSecurity.allowed_identifier?("\u1100\u1161\u032D")

    assert UnicodeSecurity.allowed_identifier?("\u0CC6\u0CC2\u0CD5")
    refute UnicodeSecurity.allowed_identifier?("\u0CC6\u0653")
    refute UnicodeSecurity.allowed_identifier?("\u0CD5")
  end

  test "validates scalar and string inputs at the public boundary" do
    for api <- [&UnicodeSecurity.identifier_status/1, &UnicodeSecurity.identifier_types/1] do
      for input <- [-1, 0x110000, 0xD800, 0xDFFF, nil, 1.0, "a"] do
        assert_raise ArgumentError, fn -> api.(input) end
      end
    end

    for input <- [nil, 42, [97]] do
      assert_raise ArgumentError, fn -> UnicodeSecurity.allowed_identifier?(input) end
    end

    for {input, reason, offset} <- [
          {"a" <> <<0xFF>>, :invalid_utf8, 1},
          {"é" <> <<0xED, 0xA0, 0x80>>, :invalid_utf8, 2},
          {:binary.copy("a", 4097), :input_too_long, 4096}
        ] do
      error = assert_raise InvalidInputError, fn -> UnicodeSecurity.allowed_identifier?(input) end
      assert {error.reason, error.byte_offset} == {reason, offset}
    end
  end

  test "identifier APIs operate with only compiled runtime modules and no source tree" do
    beam_directory = Application.app_dir(:unicode_security, "ebin")

    loader =
      Enum.map_join(
        [
          UnicodeSecurity,
          UnicodeSecurity.Identifier,
          UnicodeSecurity.Normalization,
          UnicodeSecurity.Data.Normalization,
          Data,
          UnicodeSecurity.Utf8,
          InvalidInputError
        ],
        "\n",
        fn module ->
          path = Path.join(beam_directory, Atom.to_string(module))
          ":code.load_abs(String.to_charlist(#{inspect(path)}))"
        end
      )

    verification = """
    :allowed = UnicodeSecurity.identifier_status(?a)
    [:recommended] = UnicodeSecurity.identifier_types(?a)
    true = UnicodeSecurity.allowed_identifier?("paypal")
    false = UnicodeSecurity.allowed_identifier?("pay\u200Dpal")
    false = Code.ensure_loaded?(UnicodeSecurity.UnicodeData.IdentifierParser)
    """

    assert {"", 0} = ElixirRunner.run(loader <> "\n" <> verification, cd: System.tmp_dir!())
  end

  test "parses versioned status and type data with sorted records and type sets" do
    assert IdentifierParser.statuses!(@status <> "0062; Restricted\n0041; Allowed\n") == [
             {0x41, 0x41, :allowed},
             {0x62, 0x62, :restricted}
           ]

    assert IdentifierParser.types!(@types <> "018D; Technical Obsolete\n0041; Recommended\n") == [
             {0x41, 0x41, [:recommended]},
             {0x018D, 0x018D, [:obsolete, :technical]}
           ]

    assert IdentifierParser.types!(
             @types <>
               "0041; Not_Character Deprecated Default_Ignorable Not_NFKC Not_XID Exclusion Obsolete Technical Uncommon_Use Limited_Use Inclusion Recommended\n"
           ) == [
             {0x41, 0x41,
              [
                :default_ignorable,
                :deprecated,
                :exclusion,
                :inclusion,
                :limited_use,
                :not_character,
                :not_nfkc,
                :not_xid,
                :obsolete,
                :recommended,
                :technical,
                :uncommon_use
              ]}
           ]
  end

  test "rejects malformed identifier headers, defaults, ranges and properties" do
    for {parser, header} <- [
          {&IdentifierParser.statuses!/1, @status},
          {&IdentifierParser.types!/1, @types}
        ] do
      for input <- [
            "",
            String.replace(header, "18.0.0", "17.0.0"),
            header <> "# Version: 17.0.0\n",
            String.replace(header, "0000..10FFFF", "0000..FFFF"),
            header <> String.replace(header, "# Identifier", "# ignored Identifier"),
            header <> "0041",
            header <> "0041; Allowed; extra",
            header <> "ZZZZ; Allowed",
            header <> "0042..0041; Allowed",
            header <> "110000; Allowed",
            header <> "D800; Allowed",
            header <> "D7FF..E000; Allowed",
            header <> "0041..0042; Allowed\n0042; Allowed",
            header <> "0041; Allowed\n0041; Allowed"
          ] do
        assert_raise ArgumentError, fn -> parser.(input) end
      end
    end

    for value <- ["Unknown", "", "Allowed Restricted"] do
      assert_raise ArgumentError, fn ->
        IdentifierParser.statuses!(@status <> "0041; #{value}\n")
      end
    end

    for value <- ["Unknown", "", "Recommended Recommended", "Recommended recommended"] do
      assert_raise ArgumentError, fn ->
        IdentifierParser.types!(@types <> "0041; #{value}\n")
      end
    end
  end

  defp reference_property(name) do
    Path.join(Source.directory(File.cwd!()), name)
    |> File.stream!()
    |> Stream.map(fn line -> line |> String.split("#", parts: 2) |> hd() |> String.trim() end)
    |> Stream.reject(&(&1 == ""))
    |> Enum.reduce(%{}, fn line, acc ->
      [range, value] = line |> String.split(";") |> Enum.map(&String.trim/1)
      bounds = range |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))
      Enum.reduce(hd(bounds)..List.last(bounds), acc, &Map.put(&2, &1, value))
    end)
  end

  defp canonical_decomposition_scalars do
    Source.directory(File.cwd!())
    |> Path.join("UnicodeData.txt")
    |> File.stream!()
    |> Stream.map(&String.split(&1, ";"))
    |> Stream.filter(fn fields ->
      case Enum.at(fields, 5) do
        nil -> false
        decomposition -> Regex.match?(~r/\A[0-9A-F]+(?: [0-9A-F]+)*\z/, decomposition)
      end
    end)
    |> Enum.map(fn [code | _fields] -> String.to_integer(code, 16) end)
  end

  defp explicit_rescues do
    reference_property("IdentifierStatus.txt")
    |> Map.keys()
    |> Enum.reject(&(&1 in 0xAC00..0xD7A3))
    |> Enum.map(&Normalization.nfd_scalars([&1]))
    |> Enum.filter(fn decomposition ->
      length(decomposition) > 1 and Enum.any?(decomposition, &(Data.status(&1) == :restricted))
    end)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.group_by(&hd/1)
  end
end
