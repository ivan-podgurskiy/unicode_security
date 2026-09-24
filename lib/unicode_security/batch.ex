defmodule UnicodeSecurity.Batch do
  @moduledoc false

  alias UnicodeSecurity.{BatchItem, Check, Policy, Reason, Result}

  @spec audit(Enumerable.t(), term()) :: Enumerable.t()
  def audit(enumerable, options) do
    policy = Policy.resolve!(options)
    validate_enumerable!(enumerable)
    stream_items(enumerable, policy)
  end

  @doc false
  @spec item(term(), non_neg_integer(), Policy.t()) :: BatchItem.t()
  def item(input, index, policy) do
    result =
      if is_binary(input),
        do: Check.check_resolved(input, policy),
        else: invalid_item(input, policy)

    %BatchItem{index: index, input: input, result: result}
  end

  defp stream_items(enumerable, policy) do
    enumerable
    |> Stream.with_index()
    |> Stream.map(fn {input, index} -> item(input, index, policy) end)
  end

  defp invalid_item(input, policy) do
    reason = %Reason{
      code: :invalid_item_type,
      severity: Policy.severity(policy.preset, :invalid_item_type),
      message: "Batch item is not a binary",
      byte_offset: nil,
      codepoint_index: nil,
      details: %{actual_type: actual_type(input)}
    }

    %Result{
      input: input,
      type: policy.type,
      policy: policy.preset,
      unicode_version: UnicodeSecurity.unicode_version(),
      valid_input?: false,
      verdict: Policy.verdict([reason]),
      reasons: [reason]
    }
  end

  defp validate_enumerable!(enumerable) do
    if Enumerable.impl_for(enumerable) == nil,
      do: raise(ArgumentError, "expected an enumerable")

    :ok
  end

  defp actual_type(value) when is_atom(value), do: :atom
  defp actual_type(value) when is_integer(value), do: :integer
  defp actual_type(value) when is_float(value), do: :float
  defp actual_type(value) when is_list(value), do: :list
  defp actual_type(value) when is_tuple(value), do: :tuple
  defp actual_type(value) when is_map(value), do: :map
  defp actual_type(value) when is_bitstring(value), do: :bitstring
  defp actual_type(value) when is_function(value), do: :function
  defp actual_type(value) when is_pid(value), do: :pid
  defp actual_type(value) when is_port(value), do: :port
  defp actual_type(value) when is_reference(value), do: :reference
end
