defmodule UnicodeSecurity.DomainKeyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias UnicodeSecurity.Domain
  alias UnicodeSecurity.Domain.Key

  test "skeleton payload separators cannot impersonate label boundaries" do
    assert Domain.key(Domain.validate!("a۰b.c")) == "a%2Eb.c"
    assert Domain.key(Domain.validate!("a.b۰c")) == "a.b%2Ec"
    assert Key.escape("%.%2E") == "%25%2E%252E"
  end

  test "joining any nonempty finite vectors remains injective" do
    payloads = ["", ".", "%", "%2E", "a", "é", "中"]

    vectors =
      for size <- 1..3,
          vector <-
            List.duplicate(payloads, size)
            |> Enum.reduce([[]], fn choices, acc ->
              for prefix <- acc, value <- choices, do: prefix ++ [value]
            end),
          do: vector

    assert length(Enum.uniq_by(vectors, &Key.join/1)) == length(vectors)
  end

  property "nonempty vectors of arbitrary UTF-8 payloads round-trip without collisions" do
    check all(
            left <- list_of(string(:utf8, max_length: 8), min_length: 1, max_length: 5),
            right <- list_of(string(:utf8, max_length: 8), min_length: 1, max_length: 5),
            max_runs: 200
          ) do
      if left != right, do: refute(Key.join(left) == Key.join(right))
    end
  end
end
