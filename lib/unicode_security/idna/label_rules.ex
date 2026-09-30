defmodule UnicodeSecurity.Idna.LabelRules do
  @moduledoc false

  alias UnicodeSecurity.Data.Idna
  alias UnicodeSecurity.Data.Profile
  alias UnicodeSecurity.Normalization

  @type rule ::
          :not_nfc
          | :hyphen_3_4
          | :leading_hyphen
          | :trailing_hyphen
          | :label_separator
          | :leading_mark
          | :status
          | :std3

  @spec issues([non_neg_integer()]) :: [{atom(), non_neg_integer() | nil, rule()}]
  def issues([]), do: []

  def issues(scalars) do
    nfc_issues(scalars) ++
      hyphen_issues(scalars) ++
      mark_issues(scalars) ++
      scalar_issues(scalars)
  end

  defp nfc_issues(scalars) do
    if Normalization.nfc_scalars(scalars) == scalars,
      do: [],
      else: [{:domain_idna_disallowed, nil, :not_nfc}]
  end

  defp hyphen_issues(scalars) do
    last = length(scalars) - 1

    []
    |> add(Enum.at(scalars, 0) == ?-, {:domain_hyphen_rule, 0, :leading_hyphen})
    |> add(Enum.at(scalars, last) == ?-, {:domain_hyphen_rule, last, :trailing_hyphen})
    |> add(
      Enum.at(scalars, 2) == ?- and Enum.at(scalars, 3) == ?-,
      {:domain_hyphen_rule, 2, :hyphen_3_4}
    )
  end

  defp mark_issues(scalars) do
    if Profile.category(hd(scalars)) in [:mn, :mc, :me],
      do: [{:domain_idna_disallowed, 0, :leading_mark}],
      else: []
  end

  defp scalar_issues(scalars) do
    scalars
    |> Enum.with_index()
    |> Enum.flat_map(fn {scalar, index} -> scalar_issue(scalar, index) end)
  end

  defp scalar_issue(?., index), do: [{:domain_idna_disallowed, index, :label_separator}]

  defp scalar_issue(scalar, index) do
    cond do
      scalar < 128 and scalar not in ?a..?z and scalar not in ?0..?9 and scalar != ?- ->
        [{:domain_invalid_ascii, index, :std3}]

      elem(Idna.lookup(scalar), 0) not in [:valid, :deviation] ->
        [{:domain_idna_disallowed, index, :status}]

      true ->
        []
    end
  end

  defp add(list, true, item), do: list ++ [item]
  defp add(list, false, _item), do: list
end
