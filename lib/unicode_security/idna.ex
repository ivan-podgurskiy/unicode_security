defmodule UnicodeSecurity.Idna do
  @moduledoc """
  Pinned UTS #46 nontransitional IDNA processing over Unicode scalars.
  """

  alias UnicodeSecurity.Data.Idna, as: Table
  alias UnicodeSecurity.Idna.{Bidi, ContextJ, LabelRules, Punycode}
  alias UnicodeSecurity.Normalization

  @type scalar :: 0..0xD7FF | 0xE000..0x10FFFF
  @type tagged :: {integer(), non_neg_integer()}
  @type issue :: %{
          code: UnicodeSecurity.Reason.code(),
          label_index: non_neg_integer() | nil,
          origin: non_neg_integer() | nil,
          source_scope: :scalar | :label | nil,
          details: map()
        }
  @type label :: %{
          index: non_neg_integer(),
          tagged: [tagged()] | nil,
          unicode: [scalar()] | nil,
          ascii: binary() | nil,
          root?: boolean(),
          alabel?: boolean(),
          valid?: boolean(),
          issues: [issue()]
        }
  @type report :: %{
          labels: [label()],
          unicode: [scalar()] | nil,
          ascii: binary() | nil,
          trailing_dot?: boolean(),
          valid?: boolean(),
          issues: [issue()]
        }

  @spec to_unicode([integer()]) :: {:ok, [scalar()]} | {:error, [issue()]}
  def to_unicode(scalars) do
    report = process_tagged(Enum.with_index(scalars), :unicode)
    if report.valid?, do: {:ok, report.unicode}, else: {:error, validity_issues(report)}
  end

  @spec to_ascii([integer()]) :: {:ok, [0..127]} | {:error, [issue()]}
  def to_ascii(scalars) do
    report = process_tagged(Enum.with_index(scalars), :ascii)

    if report.valid?,
      do: {:ok, :binary.bin_to_list(report.ascii)},
      else: {:error, validity_issues(report)}
  end

  # :hostname is the internal public-adapter path: it applies ASCII DNS bounds
  # while accepting one final root label. Corpus-facing :ascii verifies every
  # output label has at least one octet, including a final root label.
  @spec process_tagged([tagged()], :unicode | :ascii | :hostname) :: report()
  def process_tagged(input, mode) when mode in [:unicode, :ascii, :hostname] do
    mapped = Enum.flat_map(input, &map_scalar/1)
    segments = split_labels(mapped, source_start(input))
    last_index = length(segments) - 1
    trailing_dot? = last_index > 0 and elem(List.last(segments), 0) == []

    labels =
      segments
      |> Enum.with_index()
      |> Enum.map(fn {{tagged, fallback}, index} ->
        process_label(tagged, fallback, index, index == last_index and trailing_dot?, mode)
      end)

    bidi_issues =
      labels
      |> Enum.map(fn label -> if label.root?, do: nil, else: label.unicode end)
      |> Bidi.invalid_indexes()
      |> Enum.map(fn {label_index, local, rule} ->
        label = Enum.at(labels, label_index)

        issue(:domain_bidi_rule, label_index, label_origin(label, local), label_scope(label), %{
          rule: rule
        })
      end)

    labels =
      Enum.map(labels, fn label ->
        extra = Enum.filter(bidi_issues, &(&1.label_index == label.index))
        issues = Enum.uniq(label.issues ++ extra)
        %{label | issues: issues, valid?: Enum.all?(issues, &advisory?/1)}
      end)

    length_issues = if ascii_mode?(mode), do: name_length_issues(labels, trailing_dot?), else: []
    issues = Enum.uniq(Enum.flat_map(labels, & &1.issues) ++ length_issues)
    valid? = Enum.all?(issues, &advisory?/1)

    unicode =
      if valid? do
        join_label_values(labels, :unicode)
      else
        nil
      end

    ascii =
      if valid? and ascii_mode?(mode) do
        labels |> Enum.map(& &1.ascii) |> Enum.join(".")
      else
        nil
      end

    %{
      labels: labels,
      unicode: unicode,
      ascii: ascii,
      trailing_dot?: trailing_dot?,
      valid?: valid?,
      issues: issues
    }
  end

  defp validity_issues(report), do: Enum.reject(report.issues, &advisory?/1)
  defp advisory?(issue), do: issue.code == :domain_deviation_character
  defp ascii_mode?(mode), do: mode in [:ascii, :hostname]

  defp scalar?(scalar),
    do: is_integer(scalar) and scalar >= 0 and scalar <= 0x10FFFF and scalar not in 0xD800..0xDFFF

  defp map_scalar({scalar, origin}) do
    if scalar?(scalar) do
      case Table.lookup(scalar) do
        {:ignored, _} -> []
        {:mapped, values} -> Enum.map(values, &{&1, origin})
        {_status, _} -> [{scalar, origin}]
      end
    else
      [{scalar, origin}]
    end
  end

  defp source_start([{_scalar, origin} | _]), do: origin
  defp source_start([]), do: 0

  defp split_labels(mapped, start) do
    {segments, current, fallback} =
      Enum.reduce(mapped, {[], [], start}, fn
        {?., origin}, {segments, current, fallback} ->
          {[{Enum.reverse(current), fallback} | segments], [], origin + 1}

        item, {segments, current, fallback} ->
          {segments, [item | current], fallback}
      end)

    Enum.reverse([{Enum.reverse(current), fallback} | segments])
  end

  defp process_label([], fallback, index, root?, mode) do
    issues =
      if root? and index > 0 and mode != :ascii,
        do: [],
        else: [issue(:domain_empty_label, index, fallback, :label, %{})]

    %{
      index: index,
      tagged: [],
      unicode: [],
      ascii: "",
      root?: root?,
      alabel?: false,
      valid?: issues == [],
      issues: issues
    }
  end

  defp process_label(mapped, fallback, index, _root?, mode) do
    invalid = Enum.filter(mapped, fn {scalar, _} -> not scalar?(scalar) end)

    if invalid != [] do
      issues =
        Enum.map(invalid, fn {_scalar, invalid_origin} ->
          issue(:domain_idna_disallowed, index, invalid_origin, :scalar, %{rule: :invalid_scalar})
        end)

      %{
        index: index,
        tagged: nil,
        unicode: nil,
        ascii: nil,
        root?: false,
        alabel?: false,
        valid?: false,
        issues: issues
      }
    else
      tagged = Normalization.nfc_tagged(mapped)
      scalars = Enum.map(tagged, &elem(&1, 0))

      if alabel?(scalars) do
        process_alabel(tagged, fallback, index, mode)
      else
        process_unicode_label(tagged, fallback, index, mode, false)
      end
    end
  end

  defp alabel?([?x, ?n, ?-, ?- | _]), do: true
  defp alabel?(_), do: false

  defp process_alabel(tagged, fallback, index, mode) do
    mapped_ascii = tagged |> Enum.map(&elem(&1, 0))
    origin = elem(hd(tagged), 1)
    body = Enum.drop(mapped_ascii, 4)

    cond do
      Enum.any?(body, &(&1 > 127)) ->
        failed_alabel(index, origin, :non_ascii_body)

      ascii_mode?(mode) and length(mapped_ascii) > 63 ->
        length_issue =
          issue(:domain_label_too_long, index, origin, :label, %{
            actual_bytes: length(mapped_ascii),
            maximum_bytes: 63
          })

        %{
          index: index,
          tagged: nil,
          unicode: nil,
          ascii: nil,
          root?: false,
          alabel?: true,
          valid?: false,
          issues: [length_issue]
        }

      true ->
        body_binary = :erlang.list_to_binary(body)

        case Punycode.decode(body_binary, byte_size(body_binary)) do
          {:ok, []} ->
            failed_alabel(index, origin, :empty_decode)

          {:ok, decoded} ->
            if Enum.all?(decoded, &(&1 < 128)) do
              failed_alabel(index, origin, :ascii_decode)
            else
              decoded_tagged = Enum.map(decoded, &{&1, origin})
              label = process_unicode_label(decoded_tagged, fallback, index, mode, true)
              canonical = Punycode.encode(decoded, byte_size(body_binary))

              roundtrip =
                if canonical == {:ok, body_binary},
                  do: [],
                  else: [
                    issue(:domain_invalid_alabel, index, origin, :label, %{rule: :roundtrip})
                  ]

              issues = Enum.uniq(label.issues ++ roundtrip)

              %{
                label
                | alabel?: true,
                  ascii: if(ascii_mode?(mode), do: "xn--" <> body_binary, else: nil),
                  valid?: Enum.all?(issues, &advisory?/1),
                  issues: issues
              }
            end

          {:error, _} ->
            failed_alabel(index, origin, :punycode)
        end
    end
  end

  defp failed_alabel(index, origin, rule) do
    issues = [issue(:domain_invalid_alabel, index, origin, :label, %{rule: rule})]

    %{
      index: index,
      tagged: nil,
      unicode: nil,
      ascii: nil,
      root?: false,
      alabel?: true,
      valid?: false,
      issues: issues
    }
  end

  defp process_unicode_label(tagged, fallback, index, mode, alabel?) do
    scalars = Enum.map(tagged, &elem(&1, 0))

    label_issues =
      LabelRules.issues(scalars)
      |> Enum.map(fn {code, local, rule} ->
        issue(code, index, local_origin(tagged, local, fallback), scope(alabel?, local), %{
          rule: rule
        })
      end)

    joiner_issues =
      scalars
      |> ContextJ.invalid_indexes()
      |> Enum.map(fn local ->
        issue(
          :domain_joiner_rule,
          index,
          local_origin(tagged, local, fallback),
          scope(alabel?, local),
          %{rule: :contextj}
        )
      end)

    deviations =
      tagged
      |> Enum.filter(fn {scalar, _} -> elem(Table.lookup(scalar), 0) == :deviation end)
      |> Enum.map(fn {_scalar, origin} ->
        issue(:domain_deviation_character, index, origin, scope(alabel?, 0), %{})
      end)

    issues = Enum.uniq(label_issues ++ joiner_issues ++ deviations)
    valid? = Enum.all?(issues, &advisory?/1)

    {ascii, length_issues} =
      if ascii_mode?(mode) and valid? do
        encode_label(scalars, index, local_origin(tagged, nil, fallback), alabel?)
      else
        {nil, []}
      end

    issues = issues ++ length_issues

    %{
      index: index,
      tagged: tagged,
      unicode: scalars,
      ascii: ascii,
      root?: false,
      alabel?: alabel?,
      valid?: Enum.all?(issues, &advisory?/1),
      issues: issues
    }
  end

  defp encode_label(scalars, index, origin, true) do
    # Canonical A-label bytes are assigned by the A-label branch after validation.
    if length(scalars) > 63 do
      {nil, [issue(:domain_label_too_long, index, origin, :label, %{maximum_bytes: 63})]}
    else
      {nil, []}
    end
  end

  defp encode_label(scalars, index, origin, false) do
    if Enum.all?(scalars, &(&1 < 128)) do
      ascii = :erlang.list_to_binary(scalars)

      if byte_size(ascii) <= 63,
        do: {ascii, []},
        else:
          {nil,
           [
             issue(:domain_label_too_long, index, origin, :label, %{
               actual_bytes: byte_size(ascii),
               maximum_bytes: 63
             })
           ]}
    else
      if length(scalars) > 63 do
        {nil, [issue(:domain_label_too_long, index, origin, :label, %{maximum_bytes: 63})]}
      else
        case Punycode.encode(scalars, 59) do
          {:ok, body} ->
            {"xn--" <> body, []}

          {:error, :output_too_long} ->
            {nil, [issue(:domain_label_too_long, index, origin, :label, %{maximum_bytes: 63})]}

          {:error, _} ->
            {nil, [issue(:domain_idna_disallowed, index, origin, :label, %{rule: :status})]}
        end
      end
    end
  end

  defp name_length_issues(labels, trailing_dot?) do
    if Enum.all?(labels, &is_binary(&1.ascii)) do
      name = labels |> Enum.map(& &1.ascii) |> Enum.join(".")
      length = byte_size(name) - if(trailing_dot?, do: 1, else: 0)

      if length in 1..253 do
        []
      else
        [issue(:domain_name_too_long, nil, nil, nil, %{actual_bytes: length, maximum_bytes: 253})]
      end
    else
      []
    end
  end

  defp join_label_values(labels, key) do
    labels
    |> Enum.map(&Map.fetch!(&1, key))
    |> Enum.intersperse([?.])
    |> List.flatten()
  end

  defp local_origin(tagged, nil, fallback),
    do: if(tagged == [], do: fallback, else: elem(hd(tagged), 1))

  defp local_origin(tagged, local, fallback) do
    case Enum.at(tagged, local) do
      nil -> fallback
      {_scalar, origin} -> origin
    end
  end

  defp label_origin(label, nil), do: local_origin(label.tagged || [], nil, 0)
  defp label_origin(label, local), do: local_origin(label.tagged || [], local, 0)
  defp label_scope(label), do: if(label.alabel?, do: :label, else: :scalar)
  defp scope(true, _local), do: :label
  defp scope(false, nil), do: :label
  defp scope(false, _local), do: :scalar

  defp issue(code, label_index, origin, source_scope, details) do
    %{
      code: code,
      label_index: label_index,
      origin: origin,
      source_scope: source_scope,
      details: details
    }
  end
end
