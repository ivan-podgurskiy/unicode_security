defmodule UnicodeSecurity.PolicyTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Data.Scripts
  alias UnicodeSecurity.Policy
  alias UnicodeSecurity.Reason
  alias UnicodeSecurity.Result

  test "public structs retain exact fields and partial-result defaults" do
    assert Map.from_struct(struct(Result)) == %{
             input: nil,
             type: nil,
             policy: nil,
             verdict: nil,
             scripts: nil,
             mixed_script?: nil,
             mixed_number?: nil,
             restriction_level: nil,
             skeleton: nil,
             unicode_version: nil,
             domain: nil,
             valid_input?: true,
             reasons: []
           }

    assert Map.from_struct(struct(Reason)) == %{
             code: nil,
             severity: nil,
             message: nil,
             byte_offset: nil,
             codepoint_index: nil,
             details: %{}
           }
  end

  test "resolves every supported type default and preset minimum" do
    for {type, preset, minimum} <- [
          {:username, :default, :moderately_restrictive},
          {:tenant_slug, :default, :moderately_restrictive},
          {:organization_name, :permissive, :minimally_restrictive}
        ] do
      assert Policy.resolve!(type: type) == %{
               type: type,
               preset: preset,
               minimum: minimum,
               allowed_scripts: :all,
               denied_scripts: []
             }

      for {policy, minimum} <- [
            {:strict, :highly_restrictive},
            {:default, :moderately_restrictive},
            {:permissive, :minimally_restrictive}
          ] do
        assert %{preset: ^policy, minimum: ^minimum} = Policy.resolve!(type: type, policy: policy)
      end
    end
  end

  test "normalizes script lists but preserves an explicitly empty allowlist" do
    assert %{allowed_scripts: [:common, :greek, :inherited, :latin], denied_scripts: [:cyrillic]} =
             Policy.resolve!(
               type: :username,
               allowed_scripts: [:latin, :common, :greek, :inherited, :latin],
               denied_scripts: [:cyrillic, :cyrillic]
             )

    assert %{allowed_scripts: [], denied_scripts: []} =
             Policy.resolve!(type: :username, allowed_scripts: [], denied_scripts: [])
  end

  test "rejects malformed, duplicate, unknown and unsupported configuration safely" do
    for options <- [
          nil,
          %{},
          :options,
          "secret",
          [],
          [:type],
          [{"type", :username}],
          [{:type, :username, :extra}],
          [{:type, :username} | :tail],
          [type: :username, policy: :strict, policy: :strict],
          [type: :username, type: :username],
          [type: :username, allowed_scripts: [], allowed_scripts: []],
          [type: :username, denied_scripts: [], denied_scripts: []],
          [type: :domain],
          [type: :unknown],
          [type: nil],
          [type: "username"],
          [type: :username, unknown: "secret"],
          [type: :username, policy: :unknown],
          [type: :username, policy: nil],
          [type: :username, policy: "strict"]
        ] do
      error = assert_raise ArgumentError, fn -> Policy.resolve!(options) end
      refute Exception.message(error) =~ "secret"
    end

    for key <- [:allowed_scripts, :denied_scripts],
        scripts <- [
          nil,
          :all,
          :latin,
          "latin",
          [:unknown_script],
          ["latin"],
          [:jpan],
          [:hanb],
          [:hntl],
          [:kore],
          [nil],
          [1],
          [:latin | :tail]
        ] do
      assert_raise ArgumentError, fn -> Policy.resolve!([{:type, :username}, {key, scripts}]) end
    end

    for scripts <- [[:latin], [:latin, :latin], [:common], [:inherited]] do
      assert_raise ArgumentError, fn ->
        Policy.resolve!(type: :username, allowed_scripts: scripts, denied_scripts: scripts)
      end
    end
  end

  test "uses the literal generic reason severity matrix for all presets" do
    for {code, strict, default, permissive} <- [
          {:invalid_item_type, :critical, :critical, :critical},
          {:invalid_utf8, :critical, :critical, :critical},
          {:input_too_long, :critical, :critical, :critical},
          {:empty_input, :high, :high, :high},
          {:profile_syntax, :high, :high, :medium},
          {:restricted_character, :high, :high, :medium},
          {:invalid_join_control_context, :high, :high, :medium},
          {:disallowed_script, :high, :high, :medium},
          {:denied_script, :high, :high, :medium},
          {:default_ignorable, :critical, :high, :high},
          {:bidi_control, :critical, :high, :high},
          {:mixed_scripts, :high, :medium, :low},
          {:mixed_numbers, :high, :medium, :low},
          {:restriction_level_below_policy, :high, :medium, :low}
        ] do
      assert Policy.severity(:strict, code) == strict
      assert Policy.severity(:default, code) == default
      assert Policy.severity(:permissive, code) == permissive
    end
  end

  test "verdict uses the highest severity irrespective of reason ordering" do
    assert Policy.verdict([]) == :safe

    for {severity, verdict} <- [
          {:info, :safe},
          {:low, :suspicious},
          {:medium, :suspicious},
          {:high, :dangerous},
          {:critical, :dangerous}
        ] do
      reason = struct(Reason, severity: severity)
      assert Policy.verdict([reason]) == verdict
      assert Policy.verdict([struct(Reason, severity: :info), reason]) == verdict
      assert Policy.verdict([reason, struct(Reason, severity: :info)]) == verdict
    end

    severities = [:info, :low, :medium, :high, :critical]

    for {first, verdicts} <- [
          {:info, [:safe, :suspicious, :suspicious, :dangerous, :dangerous]},
          {:low, [:suspicious, :suspicious, :suspicious, :dangerous, :dangerous]},
          {:medium, [:suspicious, :suspicious, :suspicious, :dangerous, :dangerous]},
          {:high, [:dangerous, :dangerous, :dangerous, :dangerous, :dangerous]},
          {:critical, [:dangerous, :dangerous, :dangerous, :dangerous, :dangerous]}
        ] do
      actual =
        Enum.map(severities, fn second ->
          Policy.verdict([struct(Reason, severity: first), struct(Reason, severity: second)])
        end)

      assert actual == verdicts
    end
  end

  test "minimum comparison follows the complete standards restriction ordering" do
    rows = [
      {:ascii, [false, false, false, false, false, false]},
      {:single_script_restrictive, [true, false, false, false, false, false]},
      {:highly_restrictive, [true, true, false, false, false, false]},
      {:moderately_restrictive, [true, true, true, false, false, false]},
      {:minimally_restrictive, [true, true, true, true, false, false]},
      {:unrestricted, [true, true, true, true, true, false]}
    ]

    levels = [
      :ascii,
      :single_script_restrictive,
      :highly_restrictive,
      :moderately_restrictive,
      :minimally_restrictive,
      :unrestricted
    ]

    for {actual, expected} <- rows do
      assert Enum.map(levels, &Policy.below_minimum?(actual, &1)) == expected
    end
  end

  test "generated script lookup accepts only closed ordinary names and any term" do
    for name <- [:latin, :greek, :cyrillic, :common, :inherited, :unknown, :han] do
      assert Scripts.known_script?(name)
    end

    for term <- [
          :jpan,
          :hanb,
          :hntl,
          :kore,
          :not_a_script,
          nil,
          "latin",
          1,
          [],
          %{},
          {:latin},
          [:latin | :tail],
          fn -> :latin end
        ] do
      refute Scripts.known_script?(term)
    end
  end
end
