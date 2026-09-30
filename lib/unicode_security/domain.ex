defmodule UnicodeSecurity.Domain do
  @moduledoc false

  alias UnicodeSecurity.Check
  alias UnicodeSecurity.Confusables
  alias UnicodeSecurity.Domain.Key
  alias UnicodeSecurity.Domain.Reasons
  alias UnicodeSecurity.Domain.Source
  alias UnicodeSecurity.DomainLabel
  alias UnicodeSecurity.DomainResult
  alias UnicodeSecurity.Idna
  alias UnicodeSecurity.InvalidDomainError
  alias UnicodeSecurity.Normalization
  alias UnicodeSecurity.Policy
  alias UnicodeSecurity.Result
  alias UnicodeSecurity.Scripts
  alias UnicodeSecurity.Utf8

  @type validated :: %{
          input: binary(),
          decoded: [{non_neg_integer(), non_neg_integer()}],
          report: Idna.report(),
          units: [Source.unit()],
          label_skeletons: [binary()]
        }
  @type prepared :: %{
          input: binary(),
          decoded: [{non_neg_integer(), non_neg_integer()}],
          nfd: [non_neg_integer()],
          skeleton: binary(),
          unicode_vector: [binary()],
          labels: [map()],
          scripts: [atom()],
          resolved: :all | [atom()],
          units: [Source.unit()]
        }

  @hostname_syntax [?:, ?/, ?\\, ?@, ??, ?#, ?[, ?], ?*]

  @spec check_decoded(binary(), [{non_neg_integer(), non_neg_integer()}], Policy.t(), Result.t()) ::
          Result.t()
  def check_decoded(input, decoded, policy, result) do
    units = Source.units(input, decoded)
    report = process(decoded)
    domain_issues = report.issues ++ hostname_issues(decoded, report, units)
    domain_reasons = Enum.map(domain_issues, &Reasons.from_issue(&1, units, decoded, policy))

    labels =
      report.labels
      |> Enum.map(fn label ->
        unit = Enum.find(units, &(&1.kind == :label and &1.label_index == label.index))
        relevant = Enum.filter(domain_reasons, &(&1.details.label_index == label.index))
        label_result(label, unit, decoded, policy, relevant)
      end)

    reasons = Reasons.sort(domain_reasons ++ Enum.flat_map(labels, & &1.reasons))
    valid? = report.valid? and not Enum.any?(domain_reasons, &Reasons.validity?/1)

    domain = %DomainResult{
      unicode: if(valid?, do: scalars_to_binary(report.unicode), else: nil),
      ascii: if(valid?, do: report.ascii, else: nil),
      labels: labels,
      trailing_dot?: report.trailing_dot?,
      mapped?: if(valid?, do: scalars_to_binary(report.unicode) != input, else: nil),
      valid_idna?: report.valid?
    }

    if valid? do
      nonroot = Enum.reject(labels, & &1.root?)
      raw_levels = Enum.map(nonroot, & &1.restriction_level)

      %{
        result
        | valid_input?: true,
          domain: domain,
          skeleton: Key.join(Enum.map(nonroot, & &1.skeleton)),
          scripts: nonroot |> Enum.flat_map(& &1.scripts) |> Enum.uniq() |> Enum.sort(),
          mixed_script?: Enum.any?(nonroot, & &1.mixed_script?),
          mixed_number?: Enum.any?(nonroot, & &1.mixed_number?),
          restriction_level: weakest(raw_levels),
          reasons: reasons,
          verdict: Policy.verdict(reasons)
      }
    else
      %{
        result
        | valid_input?: false,
          domain: domain,
          reasons: reasons,
          verdict: Policy.verdict(reasons)
      }
    end
  end

  @spec validate!(binary()) :: validated()
  def validate!(input) when is_binary(input) do
    decoded = Utf8.decode!(input)
    units = Source.units(input, decoded)
    report = process(decoded)
    policy = Policy.resolve!(type: :domain)

    reasons =
      (report.issues ++ hostname_issues(decoded, report, units))
      |> Enum.map(&Reasons.from_issue(&1, units, decoded, policy))
      |> Reasons.sort()

    case Enum.find(reasons, &Reasons.validity?/1) do
      nil ->
        label_skeletons =
          report.labels
          |> Enum.reject(& &1.root?)
          |> Enum.map(&Confusables.skeleton_scalars(&1.unicode))

        %{
          input: input,
          decoded: decoded,
          report: report,
          units: units,
          label_skeletons: label_skeletons
        }

      reason ->
        raise InvalidDomainError,
          reason: reason.code,
          byte_offset: reason.byte_offset,
          label_index: reason.details.label_index
    end
  end

  def validate!(_input), do: raise(ArgumentError, "expected a binary input")

  @spec key(validated()) :: binary()
  def key(validated), do: Key.join(validated.label_skeletons)

  @spec prepare(validated(), binary()) :: prepared()
  def prepare(validated, key) do
    idna_labels = Enum.reject(validated.report.labels, & &1.root?)

    labels =
      Enum.zip(idna_labels, validated.label_skeletons)
      |> Enum.map(fn {label, skeleton} ->
        %{
          unicode: scalars_to_binary(label.unicode),
          skeleton: skeleton,
          scripts: Scripts.scripts_scalars(label.unicode),
          resolved: resolved(label.unicode)
        }
      end)

    normalized = Enum.flat_map(idna_labels, & &1.unicode)
    original = Enum.map(validated.decoded, &elem(&1, 0))

    %{
      input: validated.input,
      decoded: validated.decoded,
      nfd: Normalization.nfd_scalars(original),
      skeleton: key,
      unicode_vector: Enum.map(labels, & &1.unicode),
      labels: labels,
      scripts: normalized |> Scripts.scripts_scalars(),
      resolved: resolved(normalized),
      units: validated.units
    }
  end

  defp process(decoded) do
    decoded
    |> Enum.with_index()
    |> Enum.map(fn {{scalar, _offset}, index} -> {scalar, index} end)
    |> Idna.process_tagged(:hostname)
  end

  defp label_result(label, unit, decoded, policy, domain_reasons) do
    common = %DomainLabel{
      index: label.index,
      input: unit.input,
      byte_offset: unit.byte_offset,
      byte_length: unit.byte_length,
      codepoint_index: unit.codepoint_index,
      codepoint_count: unit.codepoint_count,
      root?: label.root?,
      unicode: if(label.unicode, do: scalars_to_binary(label.unicode), else: nil),
      ascii: label.ascii,
      mapped?: if(label.unicode, do: scalars_to_binary(label.unicode) != unit.input, else: nil),
      valid_idna?: label.valid?
    }

    cond do
      label.root? ->
        %{common | verdict: :safe, reasons: []}

      not label.valid? ->
        reasons = Reasons.sort(domain_reasons)
        %{common | reasons: reasons, verdict: Policy.verdict(reasons)}

      true ->
        offsets = normalized_offsets(label)
        facts = Check.analyze_decoded(offsets, policy, %Result{})
        security_reasons = Enum.map(facts.reasons, &translate_security(&1, label, unit, decoded))
        reasons = Reasons.sort(domain_reasons ++ security_reasons)

        %{
          common
          | skeleton: facts.skeleton,
            scripts: facts.scripts,
            resolved_scripts: resolved(label.unicode),
            mixed_script?: facts.mixed_script?,
            mixed_number?: facts.mixed_number?,
            restriction_level: facts.restriction_level,
            verdict: Policy.verdict(reasons),
            reasons: reasons
        }
    end
  end

  defp normalized_offsets(label) do
    {items, _offset} =
      Enum.map_reduce(label.tagged, 0, fn {scalar, _origin}, offset ->
        {{scalar, offset}, offset + byte_size(<<scalar::utf8>>)}
      end)

    items
  end

  defp translate_security(reason, label, unit, decoded) do
    {offset, cp_index, scope} =
      if is_nil(reason.codepoint_index) do
        {nil, nil, nil}
      else
        origin =
          if label.alabel?,
            do: unit.codepoint_index,
            else: label.tagged |> Enum.at(reason.codepoint_index) |> elem(1)

        {_scalar, byte_offset} = Enum.at(decoded, origin)
        {byte_offset, origin, if(label.alabel?, do: :label, else: :scalar)}
      end

    context = %{
      label_index: label.index,
      label: unit.input,
      original_byte_offset: offset
    }

    details =
      if scope,
        do: Map.merge(reason.details, Map.put(context, :source_scope, scope)),
        else: Map.merge(reason.details, context)

    %{reason | byte_offset: offset, codepoint_index: cp_index, details: details}
  end

  defp hostname_issues(decoded, report, units) do
    raw =
      decoded
      |> Enum.with_index()
      |> Enum.filter(fn {{scalar, _offset}, _index} -> scalar in @hostname_syntax end)
      |> Enum.map(fn {{scalar, _offset}, index} ->
        hostname_syntax_issue(index, units, scalar)
      end)

    normalized =
      report.labels
      |> Enum.flat_map(fn label ->
        (label.tagged || [])
        |> Enum.filter(fn {scalar, _origin} -> scalar in @hostname_syntax end)
        |> Enum.map(fn {scalar, origin} -> hostname_syntax_issue(origin, units, scalar) end)
      end)

    ip =
      if ipv4?(report.labels) do
        [
          %{
            code: :domain_invalid_hostname,
            label_index: nil,
            origin: nil,
            source_scope: nil,
            details: %{rule: :ip_literal}
          }
        ]
      else
        []
      end

    Enum.uniq(raw ++ normalized ++ ip)
  end

  defp hostname_syntax_issue(origin, units, scalar) do
    label_index =
      Enum.find_value(units, fn unit ->
        if unit.kind == :label and origin >= unit.codepoint_index and
             origin < unit.codepoint_index + unit.codepoint_count,
           do: unit.label_index
      end)

    %{
      code: :domain_invalid_hostname,
      label_index: label_index,
      origin: origin,
      source_scope: :scalar,
      details: %{rule: :hostname_syntax, codepoint: scalar}
    }
  end

  defp ipv4?(labels) do
    nonroot = Enum.reject(labels, & &1.root?)

    length(nonroot) == 4 and
      Enum.all?(nonroot, fn label ->
        if is_binary(label.ascii) and label.ascii != "" and
             String.match?(label.ascii, ~r/\A[0-9]+\z/) do
          digits = String.trim_leading(label.ascii, "0")
          digits == "" or (byte_size(digits) <= 3 and String.to_integer(digits) <= 255)
        else
          false
        end
      end)
  end

  defp weakest([first | rest]) do
    Enum.reduce(rest, first, fn level, weakest ->
      if Policy.below_minimum?(level, weakest), do: level, else: weakest
    end)
  end

  defp resolved(scalars) do
    case Scripts.resolved_set(scalars) do
      :all -> :all
      set -> set |> MapSet.to_list() |> Enum.sort()
    end
  end

  defp scalars_to_binary(scalars), do: scalars |> Enum.map(&<<&1::utf8>>) |> IO.iodata_to_binary()
end
