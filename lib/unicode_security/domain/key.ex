defmodule UnicodeSecurity.Domain.Key do
  @moduledoc false

  @spec escape(binary()) :: binary()
  def escape(skeleton) do
    for <<scalar::utf8 <- skeleton>>, into: "" do
      case scalar do
        ?% -> "%25"
        ?. -> "%2E"
        _ -> <<scalar::utf8>>
      end
    end
  end

  @spec join([binary()]) :: binary()
  def join(skeletons), do: Enum.map_join(skeletons, ".", &escape/1)
end
