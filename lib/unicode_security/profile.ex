defmodule UnicodeSecurity.Profile do
  @moduledoc false

  alias UnicodeSecurity.Data.Profile, as: Data
  alias UnicodeSecurity.Identifier
  alias UnicodeSecurity.Result

  @identifier_categories [:lu, :ll, :lt, :lm, :lo, :mn, :mc, :me, :nd]
  @punctuation_categories [:pc, :pd, :ps, :pe, :pi, :pf, :po]

  @spec syntax_rule(Result.input_type(), non_neg_integer()) ::
          nil | :whitespace | :punctuation | :unsupported_category
  def syntax_rule(type, scalar) do
    category = Data.category(scalar)

    cond do
      scalar in [0x200C, 0x200D] ->
        nil

      category in @identifier_categories ->
        nil

      exception?(type, scalar) ->
        nil

      organization_allowed?(type, scalar, category) ->
        nil

      Data.white_space?(scalar) ->
        :whitespace

      category in @punctuation_categories ->
        :punctuation

      true ->
        :unsupported_category
    end
  end

  defp organization_allowed?(:organization_name, scalar, category),
    do: Data.white_space?(scalar) or category in @punctuation_categories

  defp organization_allowed?(_type, _scalar, _category), do: false

  @spec exception?(Result.input_type(), non_neg_integer()) :: boolean()
  def exception?(:username, scalar), do: scalar in [?_, ?-, ?.]
  def exception?(:tenant_slug, scalar), do: scalar == ?-
  def exception?(:domain, scalar), do: scalar == ?-
  def exception?(:organization_name, _scalar), do: false

  # Keep punctuation as a normalization boundary: deleting it could rescue
  # characters by composing starters/marks or Hangul across the separator.
  @spec allowed_scalars?(Result.input_type(), [non_neg_integer()]) :: boolean()
  def allowed_scalars?(type, scalars) do
    scalars
    |> Enum.chunk_by(&exception?(type, &1))
    |> Enum.all?(fn [first | _rest] = run ->
      exception?(type, first) or Identifier.allowed_scalars?(run)
    end)
  end
end
