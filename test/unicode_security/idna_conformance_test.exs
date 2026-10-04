defmodule UnicodeSecurity.IdnaConformanceTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Idna
  alias UnicodeSecurity.Test.IdnaFixtures
  alias UnicodeSecurity.UnicodeData.Source

  test "all locked IDNA rows, Unicode and nontransitional ASCII" do
    text = File.read!(Path.join(Source.directory(File.cwd!()), "IdnaTestV2.txt"))
    rows = IdnaFixtures.parse!(text)

    source_rows =
      text
      |> String.split("\n")
      |> Enum.count(fn line ->
        line |> String.split("#", parts: 2) |> hd() |> String.trim() != ""
      end)

    assert length(rows) == source_rows

    for row <- rows,
        {function, expected, statuses} <- [
          {:to_unicode, row.unicode, row.unicode_status},
          {:to_ascii, row.ascii, row.ascii_status}
        ] do
      actual = apply(Idna, function, [row.source])

      if statuses == [] do
        assert actual == {:ok, expected},
               "#{function} fixture line #{row.line}: got #{inspect(actual)}, expected #{inspect({:ok, expected})}"
      else
        assert match?({:error, [_ | _]}, actual),
               "#{function} fixture line #{row.line}: got #{inspect(actual)}, statuses #{inspect(statuses)}"
      end
    end
  end
end
