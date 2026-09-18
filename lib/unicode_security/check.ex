defmodule UnicodeSecurity.Check do
  @moduledoc false

  alias UnicodeSecurity.Confusables
  alias UnicodeSecurity.Data.Bidi, as: BidiData
  alias UnicodeSecurity.Data.Numbers
  alias UnicodeSecurity.Data.Profile, as: ProfileData
  alias UnicodeSecurity.Data.Scripts, as: ScriptsData
  alias UnicodeSecurity.Identifier
  alias UnicodeSecurity.InvalidInputError
  alias UnicodeSecurity.JoinControls
  alias UnicodeSecurity.Policy
  alias UnicodeSecurity.Profile
  alias UnicodeSecurity.Reason
  alias UnicodeSecurity.Restrictions
  alias UnicodeSecurity.Result
  alias UnicodeSecurity.Scripts
  alias UnicodeSecurity.Utf8

  @messages %{
    empty_input: "Identifier is empty",
    invalid_utf8: "Input contains invalid UTF-8",
    input_too_long: "Input exceeds the byte limit",
    profile_syntax: "Character violates the type syntax",
    restricted_character: "Character has Restricted identifier status",
    default_ignorable: "Default-ignorable character is present",
    bidi_control: "Bidirectional control is present",
    invalid_join_control_context: "Join control fails the required context",
    disallowed_script: "Character has no allowed script candidate",
    denied_script: "Character has no remaining script candidate",
    mixed_scripts: "Multiple effective scripts are present",
    mixed_numbers: "Multiple decimal number systems are present",
    restriction_level_below_policy: "Restriction level is below the policy minimum"
  }

  @spec check(binary(), keyword()) :: Result.t()
  def check(input, options) do
    policy = Policy.resolve!(options)
    if not is_binary(input), do: raise(ArgumentError, "expected a binary input")

    result = %Result{
      input: input,
      type: policy.type,
      policy: policy.preset,
      unicode_version: UnicodeSecurity.unicode_version()
    }

    decode_result(input, policy, result)
  end

  defp decode_result(input, policy, result) do
    decoded = Utf8.decode!(input)
    analyze(decoded, policy, result)
  rescue
    error in InvalidInputError ->
      details = error_details(error.reason, input, error.byte_offset)
      reason = reason(policy, error.reason, error.byte_offset, nil, details)
      %{result | valid_input?: false, verdict: Policy.verdict([reason]), reasons: [reason]}
  end

  defp error_details(:input_too_long, input, _offset),
    do: %{actual_bytes: byte_size(input), maximum_bytes: 4096}

  defp error_details(:invalid_utf8, input, offset),
    do: %{invalid_byte: :binary.at(input, offset)}

  defp analyze(decoded, policy, result) do
    scalars = Enum.map(decoded, &elem(&1, 0))
    # Observed scripts, intersections and decimal systems are duplicate-invariant.
    distinct_scalars = Enum.uniq(scalars)
    scripts = Scripts.scripts_scalars(distinct_scalars)
    mixed_script? = Scripts.mixed_scalars?(distinct_scalars)

    zeros =
      distinct_scalars
      |> Enum.map(&Numbers.zero/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> Enum.sort()

    membership? = Identifier.allowed_scalars?(scalars)
    raw_level = Restrictions.level_scalars(scalars, membership?)

    adjusted_level =
      if Enum.any?(scalars, &Profile.exception?(policy.type, &1)),
        do: Restrictions.level_scalars(scalars, Profile.allowed_scalars?(policy.type, scalars)),
        else: raw_level

    invalid_joiners = scalars |> JoinControls.invalid_indexes() |> MapSet.new()

    positional =
      decoded
      |> Enum.with_index()
      |> Enum.map_reduce(%{}, fn {{scalar, offset}, index}, cache ->
        # Join validity is per occurrence, so it participates in the cache key.
        key = {scalar, MapSet.member?(invalid_joiners, index)}

        {templates, cache} =
          case Map.fetch(cache, key) do
            {:ok, templates} ->
              {templates, cache}

            :error ->
              templates = scalar_reasons(scalar, 0, 0, policy, elem(key, 1))
              {templates, Map.put(cache, key, templates)}
          end

        {Enum.map(templates, &%{&1 | byte_offset: offset, codepoint_index: index}), cache}
      end)
      |> elem(0)
      |> List.flatten()

    reasons =
      positional
      |> add_reason(scalars == [], policy, :empty_input, 0, 0, %{})
      |> add_reason(mixed_script?, policy, :mixed_scripts, nil, nil, %{
        scripts: scripts -- [:common, :inherited]
      })
      |> add_reason(length(zeros) > 1, policy, :mixed_numbers, nil, nil, %{zero_codepoints: zeros})
      |> add_reason(
        Policy.below_minimum?(adjusted_level, policy.minimum),
        policy,
        :restriction_level_below_policy,
        nil,
        nil,
        %{actual: raw_level, minimum: policy.minimum}
      )
      |> Enum.uniq_by(&{&1.byte_offset, &1.code, &1.details})
      |> Enum.sort_by(&{is_nil(&1.byte_offset), &1.byte_offset, &1.code, &1.details})

    %{
      result
      | scripts: scripts,
        mixed_script?: mixed_script?,
        mixed_number?: length(zeros) > 1,
        restriction_level: raw_level,
        skeleton: Confusables.skeleton_scalars(scalars),
        reasons: reasons,
        verdict: Policy.verdict(reasons)
    }
  end

  defp scalar_reasons(scalar, offset, index, policy, invalid_join?) do
    rule = Profile.syntax_rule(policy.type, scalar)

    restricted? =
      Identifier.status(scalar) == :restricted and not Profile.exception?(policy.type, scalar)

    []
    |> add_reason(not is_nil(rule), policy, :profile_syntax, offset, index, %{
      rule: rule,
      codepoint: scalar
    })
    |> add_reason(restricted?, policy, :restricted_character, offset, index, %{
      codepoint: scalar,
      identifier_types: Identifier.types(scalar)
    })
    |> add_reason(
      BidiData.default_ignorable?(scalar),
      policy,
      :default_ignorable,
      offset,
      index,
      %{codepoint: scalar}
    )
    |> add_reason(ProfileData.bidi_control?(scalar), policy, :bidi_control, offset, index, %{
      codepoint: scalar
    })
    |> add_reason(invalid_join?, policy, :invalid_join_control_context, offset, index, %{
      codepoint: scalar
    })
    |> Kernel.++(script_reasons(scalar, offset, index, policy))
  end

  defp script_reasons(scalar, offset, index, policy) do
    candidates = ScriptsData.extensions(scalar)

    if Enum.all?(candidates, &(&1 in [:common, :inherited])) do
      []
    else
      allowed = filter_allowed(candidates, policy.allowed_scripts)
      remaining = allowed -- policy.denied_scripts

      cond do
        allowed == [] -> script_findings(candidates, :disallowed_script, offset, index, policy)
        remaining == [] -> script_findings(allowed, :denied_script, offset, index, policy)
        true -> []
      end
    end
  end

  defp filter_allowed(candidates, :all), do: candidates
  defp filter_allowed(candidates, allowed), do: Enum.filter(candidates, &(&1 in allowed))

  defp script_findings(candidates, code, offset, index, policy),
    do: Enum.map(Enum.sort(candidates), &reason(policy, code, offset, index, %{script: &1}))

  defp add_reason(reasons, false, _policy, _code, _offset, _index, _details), do: reasons

  defp add_reason(reasons, true, policy, code, offset, index, details),
    do: [reason(policy, code, offset, index, details) | reasons]

  defp reason(policy, code, offset, index, details) do
    %Reason{
      code: code,
      severity: Policy.severity(policy.preset, code),
      message: Map.fetch!(@messages, code),
      byte_offset: offset,
      codepoint_index: index,
      details: details
    }
  end
end
