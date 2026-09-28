defmodule UnicodeSecurity.Domain.Reasons do
  @moduledoc false

  alias UnicodeSecurity.Policy
  alias UnicodeSecurity.Reason

  @messages %{
    domain_empty_label: "Domain contains an empty label",
    domain_invalid_alabel: "Domain A-label is invalid",
    domain_idna_disallowed: "Domain label violates IDNA validity",
    domain_hyphen_rule: "Domain label violates the hyphen rule",
    domain_bidi_rule: "Domain label violates the IDNA bidi rule",
    domain_joiner_rule: "Domain join control fails CONTEXTJ",
    domain_label_too_long: "Domain label exceeds the ASCII byte limit",
    domain_name_too_long: "Domain exceeds the ASCII byte limit",
    domain_invalid_ascii: "Domain label violates STD3 ASCII rules",
    domain_deviation_character: "Domain retains an IDNA deviation character",
    domain_invalid_hostname: "Input is not a hostname"
  }
  @validity Map.keys(@messages) -- [:domain_deviation_character]

  @spec from_issue(
          UnicodeSecurity.Idna.issue(),
          [UnicodeSecurity.Domain.Source.unit()],
          [{non_neg_integer(), non_neg_integer()}],
          Policy.t()
        ) :: Reason.t()
  def from_issue(issue, units, decoded, policy) do
    unit =
      Enum.find(units, fn unit ->
        unit.kind == :label and unit.label_index == issue.label_index
      end)

    {offset, cp_index} = position(issue, unit, decoded)

    context = %{
      label_index: issue.label_index,
      label: if(unit, do: unit.input, else: nil),
      original_byte_offset: offset
    }

    scope = if issue.source_scope, do: %{source_scope: issue.source_scope}, else: %{}
    details = Map.merge(issue.details, Map.merge(context, scope))

    %Reason{
      code: issue.code,
      severity: Policy.severity(policy.preset, issue.code),
      message: Map.fetch!(@messages, issue.code),
      byte_offset: offset,
      codepoint_index: cp_index,
      details: details
    }
  end

  @spec sort([Reason.t()]) :: [Reason.t()]
  def sort(reasons) do
    reasons
    |> Enum.uniq_by(&{&1.code, &1.byte_offset, &1.details})
    |> Enum.sort_by(&{is_nil(&1.byte_offset), &1.byte_offset, &1.code, &1.details})
  end

  @spec validity?(Reason.t()) :: boolean()
  def validity?(reason), do: reason.code in @validity

  defp position(%{source_scope: :label}, unit, _decoded) when not is_nil(unit),
    do: {unit.byte_offset, unit.codepoint_index}

  defp position(%{origin: nil}, _unit, _decoded), do: {nil, nil}

  defp position(%{origin: origin}, unit, decoded) do
    case Enum.at(decoded, origin) do
      {_scalar, offset} -> {offset, origin}
      nil -> {if(unit, do: unit.byte_offset + unit.byte_length, else: nil), origin}
    end
  end
end
