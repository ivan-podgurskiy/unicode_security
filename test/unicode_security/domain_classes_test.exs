defmodule UnicodeSecurity.DomainClassesTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Domain.Classes

  @precedence [:mixed_script_confusable, :whole_script_confusable, :single_script_confusable]

  test "same signature groups retain distinct Unicode vectors and ignore repetitions" do
    state =
      Classes.add(%{}, [[:latin], [:latin]], ["a", "a"])
      |> Classes.add([[:latin], [:latin]], ["a", "a"])
      |> Classes.add([[:latin], [:latin]], ["b", "a"])

    assert map_size(state) == 1
    assert state[[[:latin], [:latin]]] == MapSet.new([["a", "a"], ["b", "a"]])
    assert Classes.finish(state) == [:single_script_confusable]
  end

  test "neutral and empty resolved sets use their own precedence" do
    assert Classes.finish(
             Classes.add(%{}, [:all], ["a"])
             |> Classes.add([[:latin]], ["b"])
           ) == [:single_script_confusable]

    assert Classes.finish(
             Classes.add(%{}, [[]], ["a"])
             |> Classes.add([[:latin]], ["b"])
           ) == [:mixed_script_confusable]
  end

  test "a weaker potential class is absent when stronger labels always differ" do
    state =
      Classes.add(%{}, [[], [:cyrillic], [:latin]], ["m1", "c1", "same"])
      |> Classes.add([[], [:cyrillic], [:latin]], ["m2", "c2", "same"])
      |> Classes.add([[], [:latin], [:latin]], ["m3", "l1", "same"])

    assert Classes.finish(state) == [:mixed_script_confusable]
  end

  test "matching stronger projection exposes another actual primary class" do
    state =
      Classes.add(%{}, [[], [:cyrillic], [:latin]], ["m1", "c1", "same"])
      |> Classes.add([[], [:cyrillic], [:latin]], ["m2", "c2", "same"])
      |> Classes.add([[], [:latin], [:latin]], ["m1", "l1", "same"])
      |> Classes.add([[], [:latin], [:latin]], ["m3", "l1", "same"])

    assert Classes.finish(state) == [:mixed_script_confusable, :whole_script_confusable]
  end

  test "small correlated vectors match an independent all-pairs oracle" do
    facts = [
      {[[], [:cyrillic], [:latin]], ["m1", "c1", "x"]},
      {[[], [:cyrillic], [:latin]], ["m2", "c2", "x"]},
      {[[], [:latin], [:latin]], ["m1", "l1", "x"]},
      {[[], [:latin], [:latin]], ["m3", "l2", "x"]},
      {[:all, [:latin], [:latin]], ["n", "l1", "x"]},
      {[[:latin], [:latin], [:latin]], ["a", "l1", "x"]}
    ]

    for size <- 0..length(facts), chosen <- combinations(facts, size) do
      state =
        Enum.reduce(chosen, %{}, fn {signature, vector}, state ->
          Classes.add(state, signature, vector)
        end)

      assert Classes.finish(state) == oracle_classes(chosen)
    end
  end

  defp combinations(_facts, 0), do: [[]]
  defp combinations([], _size), do: []

  defp combinations([head | tail], size) do
    Enum.map(combinations(tail, size - 1), &[head | &1]) ++ combinations(tail, size)
  end

  defp oracle_classes(facts) do
    found =
      for {left_sig, left_values} <- facts,
          {right_sig, right_values} <- facts,
          left_values != right_values,
          reduce: MapSet.new() do
        found ->
          changed =
            Enum.zip([left_sig, left_values, right_sig, right_values])
            |> Enum.filter(fn {_a, value_a, _b, value_b} -> value_a != value_b end)

          classes = Enum.map(changed, fn {a, _, b, _} -> oracle_label_class(a, b) end)
          class = Enum.find(@precedence, &(&1 in classes))
          if class, do: MapSet.put(found, class), else: found
      end

    Enum.filter(@precedence, &MapSet.member?(found, &1))
  end

  defp oracle_label_class(a, b) do
    cond do
      a == [] or b == [] -> :mixed_script_confusable
      a == :all or b == :all -> :single_script_confusable
      Enum.any?(a, &(&1 in b)) -> :single_script_confusable
      true -> :whole_script_confusable
    end
  end
end
