defmodule UnicodeSecurity.Policy do
  @moduledoc false

  alias UnicodeSecurity.Data.Scripts
  alias UnicodeSecurity.Reason
  alias UnicodeSecurity.Result

  @defaults %{username: :default, tenant_slug: :default, organization_name: :permissive}
  @minimums %{
    strict: :highly_restrictive,
    default: :moderately_restrictive,
    permissive: :minimally_restrictive
  }
  @levels %{
    ascii: 0,
    single_script_restrictive: 1,
    highly_restrictive: 2,
    moderately_restrictive: 3,
    minimally_restrictive: 4,
    unrestricted: 5
  }
  @severities %{info: 0, low: 1, medium: 2, high: 3, critical: 4}
  @preset_indices %{strict: 0, default: 1, permissive: 2}
  @matrix %{
    invalid_utf8: {:critical, :critical, :critical},
    input_too_long: {:critical, :critical, :critical},
    empty_input: {:high, :high, :high},
    profile_syntax: {:high, :high, :medium},
    restricted_character: {:high, :high, :medium},
    invalid_join_control_context: {:high, :high, :medium},
    disallowed_script: {:high, :high, :medium},
    denied_script: {:high, :high, :medium},
    default_ignorable: {:critical, :high, :high},
    bidi_control: {:critical, :high, :high},
    mixed_scripts: {:high, :medium, :low},
    mixed_numbers: {:high, :medium, :low},
    restriction_level_below_policy: {:high, :medium, :low}
  }

  @type t :: %{
          type: Result.input_type(),
          preset: Result.preset(),
          minimum: Result.restriction_level(),
          allowed_scripts: :all | [atom()],
          denied_scripts: [atom()]
        }

  @spec resolve!(term()) :: t()
  def resolve!(options) do
    options = validate_options!(options, %{})
    type = Map.get(options, :type)
    default = fetch!(@defaults, type, "unsupported or missing type")
    preset = Map.get(options, :policy, default)
    minimum = fetch!(@minimums, preset, "unsupported policy")

    allowed =
      case Map.fetch(options, :allowed_scripts) do
        :error -> :all
        {:ok, scripts} -> normalize_scripts!(scripts)
      end

    denied = options |> Map.get(:denied_scripts, []) |> normalize_scripts!()

    if allowed != :all and Enum.any?(allowed, &(&1 in denied)) do
      raise ArgumentError, "allowed and denied scripts overlap"
    end

    %{
      type: type,
      preset: preset,
      minimum: minimum,
      allowed_scripts: allowed,
      denied_scripts: denied
    }
  end

  @spec severity(Result.preset(), Reason.code()) :: Reason.severity()
  def severity(preset, code),
    do: elem(Map.fetch!(@matrix, code), Map.fetch!(@preset_indices, preset))

  @spec verdict([Reason.t()]) :: Result.verdict()
  def verdict(reasons) do
    highest =
      Enum.reduce(reasons, 0, fn reason, rank ->
        max(rank, Map.fetch!(@severities, reason.severity))
      end)

    cond do
      highest >= 3 -> :dangerous
      highest >= 1 -> :suspicious
      true -> :safe
    end
  end

  @spec below_minimum?(Result.restriction_level(), Result.restriction_level()) :: boolean()
  def below_minimum?(actual, minimum),
    do: Map.fetch!(@levels, actual) > Map.fetch!(@levels, minimum)

  defp validate_options!([], options), do: options

  defp validate_options!([{key, value} | rest], options)
       when key in [:type, :policy, :allowed_scripts, :denied_scripts] do
    if Map.has_key?(options, key), do: raise(ArgumentError, "duplicate option")
    validate_options!(rest, Map.put(options, key, value))
  end

  defp validate_options!(_malformed, _options),
    do: raise(ArgumentError, "expected supported keyword options")

  defp normalize_scripts!(scripts) do
    validate_scripts!(scripts)
    scripts |> Enum.uniq() |> Enum.sort()
  end

  defp validate_scripts!([]), do: :ok

  defp validate_scripts!([script | rest]) do
    if not Scripts.known_script?(script), do: raise(ArgumentError, "unknown script")
    validate_scripts!(rest)
  end

  defp validate_scripts!(_malformed), do: raise(ArgumentError, "expected a proper script list")

  defp fetch!(map, key, message) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> raise ArgumentError, message
    end
  end
end
