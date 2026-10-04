defmodule UnicodeSecurity.IdnaDataTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Data.Idna
  alias UnicodeSecurity.UnicodeData.Source

  test "nontransitional payloads remain distinguishable" do
    assert Idna.lookup(?A) == {:mapped, [?a]}
    assert Idna.lookup(0xAD) == {:ignored, []}
    assert Idna.lookup(0xDF) == {:deviation, [?s, ?s]}
    assert Idna.lookup(0x3002) == {:mapped, [?.]}
    assert Idna.lookup(0xD800) == {:disallowed, []}
    assert Idna.lookup(-1) == {:disallowed, []}
    assert Idna.lookup(0x110000) == {:disallowed, []}
  end

  test "generated table matches every locked source codepoint and maximum expansion" do
    records = source_records()
    assert {0, _, _, _} = hd(records)
    assert {_, 0x10FFFF, _, _} = List.last(records)

    Enum.reduce(records, 0, fn {first, last, _status, _mapping}, next ->
      assert first == next
      last + 1
    end)

    maximum =
      Enum.reduce(records, 1, fn {_first, _last, _status, mapping}, acc ->
        max(acc, length(mapping))
      end)

    assert Idna.maximum_mapping_length() == maximum

    for {first, last, status, mapping} <- records,
        codepoint <- first..last do
      expected = if codepoint in 0xD800..0xDFFF, do: {:disallowed, []}, else: {status, mapping}
      assert Idna.lookup(codepoint) == expected
    end
  end

  test "only recognized separators can yield an accepted period after mapping" do
    records = source_records()
    separators = MapSet.new([0x2E, 0x3002, 0xFF0E, 0xFF61])

    for {first, last, status, mapping} <- records,
        status in [:valid, :mapped, :deviation],
        codepoint <- first..last,
        ?. in if(status == :mapped, do: mapping, else: [codepoint]) do
      assert MapSet.member?(separators, codepoint)
    end
  end

  # Independent fixture decoding catches parser/packer errors rather than sharing them.
  defp source_records do
    statuses = %{
      "valid" => :valid,
      "ignored" => :ignored,
      "mapped" => :mapped,
      "deviation" => :deviation,
      "disallowed" => :disallowed
    }

    Source.directory(File.cwd!())
    |> Path.join("IdnaMappingTable.txt")
    |> File.read!()
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      body = line |> String.split("#") |> hd() |> String.trim()

      if body == "" do
        []
      else
        [range, status | payload] = body |> String.split(";") |> Enum.map(&String.trim/1)
        bounds = range |> String.split("..") |> Enum.map(&String.to_integer(&1, 16))

        mapping =
          payload |> List.first("") |> String.split() |> Enum.map(&String.to_integer(&1, 16))

        [{hd(bounds), List.last(bounds), Map.fetch!(statuses, status), mapping}]
      end
    end)
  end
end
