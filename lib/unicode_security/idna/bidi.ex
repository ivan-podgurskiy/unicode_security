defmodule UnicodeSecurity.Idna.Bidi do
  @moduledoc false

  alias UnicodeSecurity.Data.Bidi, as: Data

  @ltr_allowed [:l, :en, :es, :cs, :et, :on, :bn, :nsm]
  @rtl_allowed [:r, :al, :an, :en, :es, :cs, :et, :on, :bn, :nsm]
  @either_allowed Enum.uniq(@ltr_allowed ++ @rtl_allowed)

  @spec invalid_indexes([[non_neg_integer()] | nil]) ::
          [
            {non_neg_integer(), non_neg_integer() | nil,
             :first | :allowed | :last | :mixed_digits}
          ]
  def invalid_indexes(labels) do
    active? =
      Enum.any?(labels, fn
        nil -> false
        scalars -> Enum.any?(scalars, &(Data.class(&1) in [:r, :al, :an]))
      end)

    if active? do
      labels
      |> Enum.with_index()
      |> Enum.flat_map(fn
        {nil, _index} -> []
        {[], _index} -> []
        {scalars, index} -> label_findings(scalars, index)
      end)
      |> Enum.uniq()
      |> Enum.sort_by(&sort_key/1)
    else
      []
    end
  end

  defp label_findings(scalars, label_index) do
    classes = Enum.map(scalars, &Data.class/1)
    direction = direction(hd(classes))
    first = if direction == nil, do: [{label_index, 0, :first}], else: []

    first ++
      forbidden(classes, label_index, direction) ++
      last_finding(classes, label_index, direction) ++
      mixed_digits(classes, label_index, direction)
  end

  defp sort_key({label, local, rule}) do
    rank = %{first: 0, allowed: 1, last: 2, mixed_digits: 3}
    {label, rank[rule], if(is_nil(local), do: -1, else: local)}
  end

  defp direction(:l), do: :ltr
  defp direction(class) when class in [:r, :al], do: :rtl
  defp direction(_class), do: nil

  defp forbidden(classes, label_index, direction) do
    allowed =
      case direction do
        :ltr -> @ltr_allowed
        :rtl -> @rtl_allowed
        nil -> @either_allowed
      end

    classes
    |> Enum.with_index()
    |> Enum.flat_map(fn {class, index} ->
      if class in allowed, do: [], else: [{label_index, index, :allowed}]
    end)
  end

  defp last_finding(classes, label_index, direction) do
    {last_class, last_index} =
      classes
      |> Enum.with_index()
      |> Enum.reverse()
      |> Enum.find({nil, nil}, fn {class, _index} -> class != :nsm end)

    valid_last =
      case direction do
        :ltr -> last_class in [:l, :en]
        :rtl -> last_class in [:r, :al, :en, :an]
        nil -> last_class in [:l, :r, :al, :en, :an]
      end

    if valid_last, do: [], else: [{label_index, last_index, :last}]
  end

  defp mixed_digits(classes, label_index, direction) do
    if direction == :rtl and :en in classes and :an in classes,
      do: [{label_index, nil, :mixed_digits}],
      else: []
  end
end
