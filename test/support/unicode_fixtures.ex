defmodule UnicodeSecurity.Test.UnicodeFixtures do
  @moduledoc false

  @normalization_path Path.expand(
                        "../../priv/unicode/18.0.0-draft/NormalizationTest.txt",
                        __DIR__
                      )

  def normalization_rows do
    @normalization_path
    |> File.stream!()
    |> Stream.with_index(1)
    |> Stream.map(fn {line, number} ->
      {line |> String.split("#", parts: 2) |> hd() |> String.trim(), number}
    end)
    |> Stream.reject(fn {line, _number} -> line == "" or String.starts_with?(line, "@") end)
    |> Stream.map(fn {line, number} ->
      [c1, c2, c3, c4, c5, ""] = String.split(line, ";")
      {number, Enum.map([c1, c2, c3, c4, c5], &decode_hex_sequence/1)}
    end)
  end

  def golden_corpus do
    [
      "",
      "Hello\0World!",
      "À",
      "Ǻ",
      "Å",
      "q\u0307\u0301\u0323",
      "\u0307\u0323q\u0301\u0323",
      "Ḋ\u0323",
      "\u0344\u0323",
      "가각힣",
      "ﬁ①",
      "😀\u{10FFFF}",
      "\u{1D15E}"
    ]
  end

  defp decode_hex_sequence(sequence) do
    sequence
    |> String.split()
    |> Enum.map(fn hex -> <<String.to_integer(hex, 16)::utf8>> end)
    |> IO.iodata_to_binary()
  end
end
