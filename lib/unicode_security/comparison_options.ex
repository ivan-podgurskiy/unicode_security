defmodule UnicodeSecurity.ComparisonOptions do
  @moduledoc false

  @type mode :: :optional | :required
  @type input_type :: :username | :tenant_slug | :organization_name

  @spec resolve!(term(), mode()) :: input_type() | nil
  def resolve!([], :optional), do: nil

  def resolve!([type: type], mode)
      when type in [:username, :tenant_slug, :organization_name] and
             mode in [:optional, :required],
      do: type

  def resolve!(_options, _mode), do: raise(ArgumentError, "expected supported type options")
end
