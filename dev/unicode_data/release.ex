defmodule UnicodeSecurity.UnicodeData.Release do
  @moduledoc false

  @spec non_final_source_names([map()]) :: [String.t()]
  def non_final_source_names(sources) do
    sources
    |> Enum.reject(&(&1.status == :final))
    |> Enum.map(& &1.name)
    |> Enum.sort()
  end
end
