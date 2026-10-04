defmodule UnicodeSecurity.RestrictionsTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Data.Numbers
  alias UnicodeSecurity.InvalidInputError
  alias UnicodeSecurity.Test.ElixirRunner
  alias UnicodeSecurity.UnicodeData.Parser
  alias UnicodeSecurity.UnicodeData.Source

  # Literal expectations catch order changes, raw-profile gating, lost augmentation,
  # and subtracting Latin from each set instead of dropping the whole SOSS entry.
  @levels [
    {"", :ascii},
    {"paypal", :ascii},
    {"123", :ascii},
    {"é", :single_script_restrictive},
    {"\u00B7", :single_script_restrictive},
    {"\u2019", :single_script_restrictive},
    {"\u0115", :single_script_restrictive},
    {"\u0622", :single_script_restrictive},
    {"ねガ", :single_script_restrictive},
    {"漢a", :single_script_restrictive},
    {"漢한", :single_script_restrictive},
    {"aねガ", :highly_restrictive},
    {"a漢한", :highly_restrictive},
    {"aー", :highly_restrictive},
    {"aね\u0301", :highly_restrictive},
    {"aअ", :moderately_restrictive},
    {"aא\u0301", :moderately_restrictive},
    {"a\u00B7अ", :moderately_restrictive},
    {"अا", :minimally_restrictive},
    {"Ωmega", :minimally_restrictive},
    {"Teχ", :minimally_restrictive},
    {"раypal", :minimally_restrictive},
    {"aअا", :minimally_restrictive},
    {"pay\u200Dpal", :unrestricted},
    {" ", :unrestricted},
    {"\u034F", :unrestricted},
    {"ㄅ", :unrestricted},
    {"漢ㄅa", :unrestricted},
    {"😀", :unrestricted}
  ]

  test "detects decimal systems only, including supplementary digits and repeated systems" do
    for input <- ["", "abc", "123", "١٢٣", "۱۲۳", "𝟘𝟙", "𝟙𝟚", "1½Ⅳ①", "١½Ⅳ①"] do
      refute UnicodeSecurity.mixed_number?(input), inspect(input)
    end

    for input <- ["1١", "٠۰", "৪8", "1𝟙", "𝟙𝟐", "1١1", "1١½Ⅳ①"] do
      assert UnicodeSecurity.mixed_number?(input), inspect(input)
    end
  end

  test "returns the first applicable restriction level from the pinned profile and script sets" do
    for {input, expected} <- @levels do
      assert UnicodeSecurity.restriction_level(input) == expected, inspect(input)
    end

    assert UnicodeSecurity.identifier_status(0x0115) == :restricted
    assert UnicodeSecurity.identifier_status(0x0622) == :allowed
    assert UnicodeSecurity.identifier_status(0x0301) == :allowed
    assert UnicodeSecurity.identifier_status(0x3105) == :restricted
    assert UnicodeSecurity.Scripts.resolved_without_latin([?a, 0x2019]) == :all

    assert UnicodeSecurity.Scripts.resolved_without_latin([?a, 0x6F22, 0x3105]) ==
             MapSet.new([:hanb])

    assert UnicodeSecurity.restriction_level(:binary.copy("a", 4096)) == :ascii
    refute UnicodeSecurity.mixed_number?(:binary.copy("1", 4096))
  end

  @tag timeout: 120_000
  test "matches all decimal scalars and absent values in independently parsed UnicodeData" do
    expected =
      Source.directory(File.cwd!())
      |> Path.join("UnicodeData.txt")
      |> File.stream!()
      |> Enum.reduce(%{}, fn line, acc ->
        [hex, _name, category, _ccc, _bidi, _decomp, decimal | _] =
          line |> String.trim() |> String.split(";", trim: false)

        if category == "Nd" do
          code = String.to_integer(hex, 16)
          Map.put(acc, code, code - String.to_integer(decimal))
        else
          acc
        end
      end)

    for code <- 0..0x10FFFF, code not in 0xD800..0xDFFF do
      assert Numbers.zero(code) == Map.get(expected, code), "U+#{Integer.to_string(code, 16)}"
    end

    for {code, zero} <- expected do
      refute UnicodeSecurity.mixed_number?(<<zero::utf8, code::utf8>>)

      assert UnicodeSecurity.mixed_number?(
               <<code::utf8, if(zero == 0x30, do: 0x660, else: 0x30)::utf8>>
             )
    end
  end

  test "parses Nd fields and rejects inconsistent decimal records and incomplete systems" do
    digits = decimal_records(0x30)
    assert Parser.decimal_zeros!(digits) == [{0x30, 0x39, 0x30}]
    assert Parser.decimal_zeros!("0041;A;Lu;0;L;;;;;N;;;;;\n") == []

    for input <- [
          String.replace(digits, "Nd;0;L;;0;0;0;", "Nd;0;L;;;0;0;"),
          String.replace(digits, "Nd;0;L;;0;0;0;", "Nd;0;L;;10;0;0;"),
          String.replace(digits, "Nd;0;L;;0;0;0;", "Nd;0;L;;x;0;0;"),
          String.replace(digits, "Nd;0;L;;0;0;0;", "Nd;0;L;;0;1;0;"),
          String.replace(digits, "Nd;0;L;;0;0;0;", "Nd;0;L;;0;0;1;"),
          String.replace(digits, "Nd;0;L;;0;0;0;", "Lo;0;L;;0;0;0;"),
          String.replace(digits, "Nd;0;L;;0;0;0;", "Nd;0;L;; 0;0;0;"),
          "0000;ZERO;Nd;0;L;;9;9;9;N;;;;;\n",
          "0030;ZERO;Nd;0;L;;0;0;0;N;;;;;\n",
          digits <> digits
        ] do
      assert_raise ArgumentError, fn -> Parser.decimal_zeros!(input) end
    end
  end

  test "validates the entire original input before any early result and preserves offsets" do
    for api <- [&UnicodeSecurity.mixed_number?/1, &UnicodeSecurity.restriction_level/1] do
      for input <- [nil, 42, [97], {:binary, "a"}] do
        assert_raise ArgumentError, fn -> api.(input) end
      end

      for {input, reason, offset} <- [
            {"1١" <> <<0xFF>>, :invalid_utf8, 3},
            {"é" <> <<0xED, 0xA0, 0x80>>, :invalid_utf8, 2},
            {"\u200D" <> <<0xC0, 0x80>>, :invalid_utf8, 3},
            {<<0xF4, 0x90, 0x80, 0x80>>, :invalid_utf8, 0},
            {<<0xE2, 0x82>>, :invalid_utf8, 0},
            {:binary.copy("a", 4097), :input_too_long, 4096}
          ] do
        error = assert_raise InvalidInputError, fn -> api.(input) end
        assert {error.reason, error.byte_offset} == {reason, offset}
      end
    end
  end

  test "matches literal golden results on every runtime and works without sources or dev modules" do
    rows = File.read!("test/fixtures/golden/restrictions_v34.term")
    {goldens, []} = Code.eval_string(rows)

    for {input, expected} <- goldens do
      assert UnicodeSecurity.restriction_level(input) == expected
    end

    beam_directory = Application.app_dir(:unicode_security, "ebin")

    loader =
      Enum.map_join(
        [
          UnicodeSecurity,
          UnicodeSecurity.Restrictions,
          UnicodeSecurity.Scripts,
          UnicodeSecurity.Identifier,
          UnicodeSecurity.Normalization,
          UnicodeSecurity.Data.Scripts,
          UnicodeSecurity.Data.Identifier,
          UnicodeSecurity.Data.Normalization,
          Numbers,
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
    for {input, level} <- #{rows |> String.trim()} do
      ^level = UnicodeSecurity.restriction_level(input)
    end
    true = UnicodeSecurity.mixed_number?("1١")
    false = UnicodeSecurity.mixed_number?("١½Ⅳ①")
    false = Code.ensure_loaded?(UnicodeSecurity.UnicodeData.Parser)
    """

    assert {"", 0} = ElixirRunner.run(loader <> "\n" <> verification, cd: System.tmp_dir!())
  end

  defp decimal_records(zero) do
    Enum.map_join(0..9, fn value ->
      code =
        (zero + value) |> Integer.to_string(16) |> String.upcase() |> String.pad_leading(4, "0")

      "#{code};DIGIT;Nd;0;L;;#{value};#{value};#{value};N;;;;;\n"
    end)
  end
end
