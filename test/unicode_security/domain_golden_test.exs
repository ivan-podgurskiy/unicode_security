defmodule UnicodeSecurity.DomainGoldenTest do
  use ExUnit.Case, async: true

  test "domain public contracts are literal" do
    {%{version: 1, cases: cases}, []} = Code.eval_file("test/fixtures/golden/domain_v1.term")

    for {label, function, arguments, expected} <- cases do
      actual =
        if match?(%UnicodeSecurity.InvalidDomainError{}, expected) do
          try do
            apply(UnicodeSecurity, function, arguments)
            flunk("expected InvalidDomainError: " <> label)
          rescue
            error in UnicodeSecurity.InvalidDomainError -> error
          end
        else
          raw = apply(UnicodeSecurity, function, arguments)
          if function == :audit, do: Enum.to_list(raw), else: raw
        end

      assert actual == expected, label

      if match?(%UnicodeSecurity.InvalidDomainError{}, expected),
        do: assert(Exception.message(actual) == "Input is not a valid domain name", label)
    end
  end
end
