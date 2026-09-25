defmodule UnicodeSecurity.CollectionGoldenTest do
  use ExUnit.Case, async: true

  test "versioned comparison and collection contracts are literal" do
    for path <- [
          "test/fixtures/golden/comparison_v1.term",
          "test/fixtures/golden/collection_v1.term"
        ] do
      {%{version: 1, cases: cases}, []} = Code.eval_file(path)

      for {label, function, arguments, expected} <- cases do
        assert apply(UnicodeSecurity, function, arguments) == expected, label
      end
    end
  end
end
