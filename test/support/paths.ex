defmodule UnicodeSecurity.Test.Paths do
  @moduledoc false

  # Windows reports one directory as C:\..., C:/... and c:/....
  @spec same?(binary(), binary()) :: boolean()
  def same?(left, right) when is_binary(left) and is_binary(right) do
    canonical(left) == canonical(right)
  end

  @spec canonical(binary()) :: binary()
  def canonical(path) do
    path
    |> String.replace("\\", "/")
    |> downcase_drive()
  end

  defp downcase_drive(<<drive, ":", rest::binary>>) when drive in ?A..?Z do
    <<drive + 32, ?:, rest::binary>>
  end

  defp downcase_drive(path), do: path
end
