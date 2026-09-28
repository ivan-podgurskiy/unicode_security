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
      |> Enum.sort_by(fn {label, local, rule} ->
        rank = %{first: 0, allowed: 1, last: 2, mixed_digits: 3}
        {label, rank[rule], if(is_nil(local), do: -1, else: local)}
      end)
    else
      []
    end
  end

  defp label_findings(scalars, label_index) do
    classes = Enum.map(scalars, &Data.class/1)

    direction =
      case hd(classes) do
        :l -> :ltr
        class when class in [:r, :al] -> :rtl
        _ -> nil
      end

    first = if direction == nil, do: [{label_index, 0, :first}], else: []

    allowed =
      case direction do
        :ltr -> @ltr_allowed
        :rtl -> @rtl_allowed
        nil -> @either_allowed
      end

    forbidden =
      classes
      |> Enum.with_index()
      |> Enum.flat_map(fn {class, index} ->
        if class in allowed, do: [], else: [{label_index, index, :allowed}]
      end)

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

    last = if valid_last, do: [], else: [{label_index, last_index, :last}]

    mixed_digits =
      if direction == :rtl and :en in classes and :an in classes,
        do: [{label_index, nil, :mixed_digits}],
        else: []

    first ++ forbidden ++ last ++ mixed_digits
  end
end
