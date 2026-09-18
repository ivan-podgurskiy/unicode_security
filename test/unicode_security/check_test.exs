defmodule UnicodeSecurity.CheckTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.Data.Identifier, as: IdentifierData
  alias UnicodeSecurity.{Policy, Profile, Result}

  test "version 1 golden results preserve complete literal public contracts" do
    {%{version: 1, cases: cases}, []} = Code.eval_file("test/fixtures/golden/check_v1.term")

    for {label, input, options, expected} <- cases do
      assert UnicodeSecurity.check(input, options) == expected, label
    end
  end

  test "ASCII membership includes every pinned status and control edge" do
    allowed =
      MapSet.new(
        [39, 45, 46, 58, 95] ++
          Enum.to_list(48..57) ++ Enum.to_list(65..90) ++ Enum.to_list(97..122)
      )

    for scalar <- 0..127 do
      for candidate <- IdentifierData.rescues(scalar) do
        refute Enum.all?(candidate, &(&1 <= 127))
      end

      input = <<scalar>>
      assert UnicodeSecurity.allowed_identifier?(input) == MapSet.member?(allowed, scalar)

      for type <- [:username, :tenant_slug, :organization_name],
          preset <- [:strict, :default, :permissive] do
        result = UnicodeSecurity.check(input <> "m" <> input, type: type, policy: preset)
        assert_facts(result)
        positional = Enum.reject(result.reasons, &is_nil(&1.byte_offset))
        first = Enum.filter(positional, &(&1.byte_offset == 0))
        last = Enum.filter(positional, &(&1.byte_offset == 2))

        assert Enum.map(first, &{&1.code, &1.severity, &1.details}) ==
                 Enum.map(last, &{&1.code, &1.severity, &1.details})

        assert Enum.all?(last, &(&1.codepoint_index == 2))
      end
    end
  end

  test "repeated joiners retain independently valid contexts and original positions" do
    result = UnicodeSecurity.check("क्\u200Dकa\u200D", type: :username)

    assert [%{byte_offset: 13, codepoint_index: 5, details: %{codepoint: 0x200D}}] =
             Enum.filter(result.reasons, &(&1.code == :invalid_join_control_context))

    assert Enum.map(
             Enum.filter(result.reasons, &(&1.code == :default_ignorable)),
             & &1.byte_offset
           ) == [6, 13]
  end

  test "safe identifiers preserve original input and standard facts" do
    for type <- [:username, :tenant_slug, :organization_name],
        input <- ["alice", "alice-smith", "1alice", "-alice-"] do
      assert %Result{
               verdict: :safe,
               input: ^input,
               type: ^type,
               valid_input?: true,
               domain: nil,
               reasons: []
             } = result = UnicodeSecurity.check(input, type: type)

      assert_facts(result)
    end

    assert UnicodeSecurity.check("alice_smith.example", type: :username).verdict == :safe
    assert UnicodeSecurity.check("m", type: :username).skeleton == "rn"
  end

  test "empty input is fully analyzed and high for every type and preset" do
    for type <- [:username, :tenant_slug, :organization_name],
        preset <- [:strict, :default, :permissive] do
      result = UnicodeSecurity.check("", type: type, policy: preset)

      assert %{
               valid_input?: true,
               policy: ^preset,
               verdict: :dangerous,
               scripts: [],
               skeleton: "",
               restriction_level: :ascii
             } = result

      assert [reason] = result.reasons

      assert {reason.code, reason.severity, reason.byte_offset, reason.codepoint_index,
              reason.details} == {:empty_input, :high, 0, 0, %{}}

      assert_facts(result)
    end
  end

  test "partial errors retain nil facts and original byte evidence before expensive work" do
    for {input, code, offset, details} <- [
          {<<255>>, :invalid_utf8, 0, %{invalid_byte: 255}},
          {"é" <> <<0xE2, 0x82>>, :invalid_utf8, 2, %{invalid_byte: 0xE2}},
          {:binary.copy("a", 4097), :input_too_long, 4096,
           %{actual_bytes: 4097, maximum_bytes: 4096}},
          {:binary.copy(<<255>>, 4097), :input_too_long, 4096,
           %{actual_bytes: 4097, maximum_bytes: 4096}}
        ] do
      result = UnicodeSecurity.check(input, type: :username)

      assert %{
               input: ^input,
               valid_input?: false,
               verdict: :dangerous,
               scripts: nil,
               mixed_script?: nil,
               mixed_number?: nil,
               restriction_level: nil,
               skeleton: nil
             } = result

      assert [reason] = result.reasons

      assert {reason.code, reason.severity, reason.byte_offset, reason.codepoint_index,
              reason.details} == {code, :critical, offset, nil, details}
    end

    assert UnicodeSecurity.check(:binary.copy("a", 4096), type: :username).valid_input?
  end

  test "programmer configuration errors precede malformed and oversized content" do
    for input <- [<<255>>, :binary.copy("a", 4097)],
        options <- [
          [],
          nil,
          %{},
          [:type],
          [{"type", :username}],
          [{:type, :username, :extra}],
          [type: :domain],
          [type: :unknown],
          [type: nil],
          [type: "username"],
          [type: :username, type: :username],
          [type: :username, policy: :strict, policy: :strict],
          [type: :username, allowed_scripts: [], allowed_scripts: []],
          [type: :username, denied_scripts: [], denied_scripts: []],
          [type: :username, policy: :bogus],
          [type: :username, unsupported: true],
          [type: :username, allowed_scripts: nil],
          [type: :username, denied_scripts: [:latin | :tail]],
          [type: :username, allowed_scripts: [:jpan]],
          [type: :username, allowed_scripts: [:latin], denied_scripts: [:latin]],
          [{:type, :username} | :tail]
        ] do
      assert_raise ArgumentError, fn -> UnicodeSecurity.check(input, options) end
    end

    for input <- [nil, 1, [], <<1::1>>] do
      assert_raise ArgumentError, fn -> UnicodeSecurity.check(input, type: :username) end
    end
  end

  test "profiles use exact categories and only explicit punctuation status exceptions" do
    for type <- [:username, :tenant_slug, :organization_name],
        scalar <- [?a, 0x301, ?1, 0x200C, 0x200D] do
      assert Profile.syntax_rule(type, scalar) == nil
    end

    for scalar <- [?_, ?-, ?.] do
      assert Profile.exception?(:username, scalar)
      assert Profile.syntax_rule(:username, scalar) == nil
    end

    assert Profile.exception?(:tenant_slug, ?-)
    refute Profile.exception?(:tenant_slug, ?_)
    assert Profile.syntax_rule(:tenant_slug, ?_) == :punctuation
    assert Profile.syntax_rule(:username, 0xA0) == :whitespace
    assert Profile.syntax_rule(:username, 0x1F600) == :unsupported_category

    for scalar <- [9, 32, 0xA0, ?_, ?-, ?(, ?), 0xAB, 0xBB, ?&] do
      assert Profile.syntax_rule(:organization_name, scalar) == nil
      refute Profile.exception?(:organization_name, scalar)
    end

    result = UnicodeSecurity.check("Acme & Co.", type: :organization_name)
    assert result.policy == :permissive
    assert result.verdict == :suspicious
    refute Enum.any?(result.reasons, &(&1.code == :profile_syntax))
    assert Enum.count(result.reasons, &(&1.code == :restricted_character)) == 3
  end

  test "raw restrictions remain independent of canonical closure and unrelated invalid scalars" do
    for input <- ["ĕ", "ĕ😀"] do
      result = UnicodeSecurity.check(input, type: :username)

      assert reason =
               Enum.find(
                 result.reasons,
                 &(&1.code == :restricted_character and &1.byte_offset == 0)
               )

      assert reason.details == %{codepoint: 0x115, identifier_types: [:uncommon_use]}
    end

    assert UnicodeSecurity.check("ĕ", type: :username).restriction_level ==
             :single_script_restrictive

    assert UnicodeSecurity.check("e\u0306", type: :username).reasons == []

    for scalars <- [[0x1100, ?-, 0x1161], [?d, ?-, 0x032D]] do
      refute Profile.allowed_scalars?(:username, scalars)
      input = List.to_string(scalars)

      assert Enum.any?(
               UnicodeSecurity.check(input, type: :username).reasons,
               &(&1.code == :restriction_level_below_policy)
             )
    end

    assert Profile.allowed_scalars?(:username, [0x1100, 0x1161])
    assert Profile.allowed_scalars?(:username, [?d, 0x032D])
    assert Profile.allowed_scalars?(:username, [?-, ?a, ?-, ?-, ?b, ?-])
  end

  test "all generic reason families carry literal preset severities and required details" do
    rows = [
      {<<255>>, [], :invalid_utf8, %{invalid_byte: 255}, [:critical, :critical, :critical]},
      {:binary.copy("a", 4097), [], :input_too_long, %{actual_bytes: 4097, maximum_bytes: 4096},
       [:critical, :critical, :critical]},
      {"", [], :empty_input, %{}, [:high, :high, :high]},
      {" ", [], :profile_syntax, %{rule: :whitespace, codepoint: 32}, [:high, :high, :medium]},
      {"_", [], :profile_syntax, %{rule: :punctuation, codepoint: 95}, [:high, :high, :medium]},
      {"😀", [], :profile_syntax, %{rule: :unsupported_category, codepoint: 0x1F600},
       [:high, :high, :medium]},
      {"ĕ", [], :restricted_character, %{codepoint: 0x115, identifier_types: [:uncommon_use]},
       [:high, :high, :medium]},
      {"\u200D", [], :invalid_join_control_context, %{codepoint: 0x200D},
       [:high, :high, :medium]},
      {"a", [allowed_scripts: []], :disallowed_script, %{script: :latin},
       [:high, :high, :medium]},
      {"a", [denied_scripts: [:latin]], :denied_script, %{script: :latin},
       [:high, :high, :medium]},
      {"\u200D", [], :default_ignorable, %{codepoint: 0x200D}, [:critical, :high, :high]},
      {"\u202E", [], :bidi_control, %{codepoint: 0x202E}, [:critical, :high, :high]},
      {"aα", [], :mixed_scripts, %{scripts: [:greek, :latin]}, [:high, :medium, :low]},
      {"1١", [], :mixed_numbers, %{zero_codepoints: [48, 0x660]}, [:high, :medium, :low]}
    ]

    for {input, overrides, code, details, severities} <- rows,
        {preset, severity} <- Enum.zip([:strict, :default, :permissive], severities) do
      result = UnicodeSecurity.check(input, [type: :tenant_slug, policy: preset] ++ overrides)
      assert finding = Enum.find(result.reasons, &(&1.code == code))
      assert finding.details == details
      assert finding.severity == severity
    end

    for {preset, severity, minimum} <- [
          {:strict, :high, :highly_restrictive},
          {:default, :medium, :moderately_restrictive},
          {:permissive, :low, :minimally_restrictive}
        ] do
      result = UnicodeSecurity.check("😀", type: :username, policy: preset)
      assert finding = Enum.find(result.reasons, &(&1.code == :restriction_level_below_policy))
      assert finding.details == %{actual: :unrestricted, minimum: minimum}
      assert finding.severity == severity
      assert {finding.byte_offset, finding.codepoint_index} == {nil, nil}
    end
  end

  test "narrow syntax includes every letter and mark category but excludes other number categories" do
    for type <- [:username, :tenant_slug, :organization_name],
        scalar <- [?A, ?a, 0x1C5, 0x2B0, 0x4E00, 0x301, 0x93E, 0x20DD, ?0] do
      assert Profile.syntax_rule(type, scalar) == nil
    end

    for type <- [:username, :tenant_slug, :organization_name],
        scalar <- [0x2160, 0xB2, ?+, ?$, ?^, 0x1F600, 0, 0xE000, 0x378] do
      assert Profile.syntax_rule(type, scalar) == :unsupported_category
    end

    for scalar <- [9, 10, 13, 0x2028, 0x2029, 0x3000] do
      assert Profile.syntax_rule(:organization_name, scalar) == nil
      assert Profile.syntax_rule(:username, scalar) == :whitespace
      assert Profile.syntax_rule(:tenant_slug, scalar) == :whitespace
    end

    assert Profile.syntax_rule(:tenant_slug, ?.) == :punctuation
  end

  test "normalized join contexts keep multiple original scalar indexes and byte offsets" do
    input = "😀a\u0301\u200Dक्\u200Dक\u0344\u200C"
    result = UnicodeSecurity.check(input, type: :username)
    contexts = Enum.filter(result.reasons, &(&1.code == :invalid_join_control_context))

    assert Enum.map(contexts, &{&1.byte_offset, &1.codepoint_index, &1.details}) == [
             {7, 3, %{codepoint: 0x200D}},
             {24, 9, %{codepoint: 0x200C}}
           ]

    assert Enum.count(result.reasons, &(&1.code == :default_ignorable)) == 3
    assert_facts(result)
  end

  test "override evidence is sorted and deduplicated at original scalar positions" do
    result = UnicodeSecurity.check("éー", type: :username, allowed_scripts: [:latin, :latin])
    findings = Enum.filter(result.reasons, &(&1.code == :disallowed_script))

    assert Enum.map(findings, &{&1.byte_offset, &1.codepoint_index, &1.details}) == [
             {2, 1, %{script: :hiragana}},
             {2, 1, %{script: :katakana}}
           ]

    assert script_reasons("\u0301", allowed_scripts: []) != []
    assert script_reasons("\u034F", allowed_scripts: []) == []

    assert script_reasons("a", allowed_scripts: [:latin], denied_scripts: [:common, :inherited]) ==
             []
  end

  test "script overrides intersect ordinary extensions before denial and retain neutral semantics" do
    assert script_reasons("ー", allowed_scripts: [:latin]) == [
             {:disallowed_script, :hiragana},
             {:disallowed_script, :katakana}
           ]

    assert script_reasons("ー", denied_scripts: [:hiragana]) == []

    assert script_reasons("ー", denied_scripts: [:hiragana, :katakana]) == [
             {:denied_script, :hiragana},
             {:denied_script, :katakana}
           ]

    assert script_reasons("ー", allowed_scripts: [:katakana], denied_scripts: [:hiragana]) == []

    assert script_reasons("a", allowed_scripts: [:common, :inherited]) == [
             {:disallowed_script, :latin}
           ]

    assert script_reasons("-\u200D", allowed_scripts: []) == []

    assert script_reasons(<<0x378::utf8>>, allowed_scripts: []) == [
             {:disallowed_script, :unknown}
           ]

    assert script_reasons("a", denied_scripts: [:latin]) == [{:denied_script, :latin}]

    assert UnicodeSecurity.check("раypal", type: :username, allowed_scripts: [:latin]).verdict ==
             :dangerous
  end

  test "independent diagnostics use original positions and deterministic positional then global order" do
    result = UnicodeSecurity.check("é\u202E\u200D1١aα", type: :username)
    positional = Enum.reject(result.reasons, &is_nil(&1.byte_offset))

    assert Enum.map(positional, &{&1.byte_offset, &1.code, &1.codepoint_index}) == [
             {2, :bidi_control, 1},
             {2, :default_ignorable, 1},
             {2, :profile_syntax, 1},
             {2, :restricted_character, 1},
             {5, :default_ignorable, 2},
             {5, :invalid_join_control_context, 2},
             {5, :restricted_character, 2}
           ]

    assert Enum.map(Enum.filter(result.reasons, &is_nil(&1.byte_offset)), & &1.code) == [
             :mixed_numbers,
             :mixed_scripts,
             :restriction_level_below_policy
           ]

    assert Enum.find(result.reasons, &(&1.code == :mixed_numbers)).details == %{
             zero_codepoints: [48, 0x660]
           }

    assert Enum.find(result.reasons, &(&1.code == :mixed_scripts)).details == %{
             scripts: [:arabic, :greek, :latin]
           }

    assert Enum.find(result.reasons, &(&1.code == :restriction_level_below_policy)).details == %{
             actual: :unrestricted,
             minimum: :moderately_restrictive
           }

    for reason <- positional do
      assert is_binary(reason.message) and byte_size(reason.message) > 0

      case reason.code do
        :profile_syntax ->
          assert reason.details == %{codepoint: 0x202E, rule: :unsupported_category}

        :restricted_character ->
          assert Map.keys(reason.details) |> Enum.sort() == [:codepoint, :identifier_types]

        _ ->
          assert Map.keys(reason.details) == [:codepoint]
      end
    end
  end

  test "valid join context suppresses only context finding and all policies use the severity matrix" do
    inputs = ["a😀", "a\u200D", "\u202E", "раypal", "1١", "aα", "क्\u200Dक", "a_ ", "ー"]

    for type <- [:username, :tenant_slug, :organization_name],
        preset <- [:strict, :default, :permissive],
        input <- inputs do
      result =
        UnicodeSecurity.check(input,
          type: type,
          policy: preset,
          denied_scripts: [:katakana, :hiragana]
        )

      assert result.verdict == Policy.verdict(result.reasons)
      assert Enum.all?(result.reasons, &(&1.severity == Policy.severity(preset, &1.code)))
      assert_facts(result)
    end

    reasons = UnicodeSecurity.check("क्\u200Dक", type: :username).reasons
    refute Enum.any?(reasons, &(&1.code == :invalid_join_control_context))
    assert Enum.any?(reasons, &(&1.code == :default_ignorable))
    assert Enum.any?(reasons, &(&1.code == :restricted_character))
  end

  property "every bounded arbitrary binary returns a result whose verdict is the maximum severity" do
    check all(
            input <- binary(max_length: 4096),
            type <- member_of([:username, :tenant_slug, :organization_name]),
            preset <- member_of([:strict, :default, :permissive]),
            overrides <-
              member_of([
                [],
                [allowed_scripts: []],
                [allowed_scripts: [:latin]],
                [denied_scripts: [:latin]],
                [allowed_scripts: [:katakana], denied_scripts: [:hiragana]]
              ]),
            max_runs: 150
          ) do
      assert %Result{} =
               result = UnicodeSecurity.check(input, [type: type, policy: preset] ++ overrides)

      assert result.input == input
      assert result.verdict == Policy.verdict(result.reasons)
      if result.valid_input?, do: assert_facts(result)
    end
  end

  property "valid scalar sequences retain primitive facts under every policy" do
    check all(input <- string(:utf8, max_length: 30), max_runs: 100) do
      result = UnicodeSecurity.check(input, type: :username, allowed_scripts: [:latin])
      assert result.valid_input?
      assert_facts(result)
    end
  end

  defp script_reasons(input, options) do
    UnicodeSecurity.check(input, [{:type, :username} | options]).reasons
    |> Enum.filter(&(&1.code in [:disallowed_script, :denied_script]))
    |> Enum.map(&{&1.code, &1.details.script})
  end

  defp assert_facts(result) do
    assert result.scripts == UnicodeSecurity.scripts(result.input)
    assert result.mixed_script? == UnicodeSecurity.mixed_script?(result.input)
    assert result.mixed_number? == UnicodeSecurity.mixed_number?(result.input)
    assert result.restriction_level == UnicodeSecurity.restriction_level(result.input)
    assert result.skeleton == UnicodeSecurity.skeleton(result.input)
    assert result.unicode_version == UnicodeSecurity.unicode_version()
  end
end
