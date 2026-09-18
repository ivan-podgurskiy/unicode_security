defmodule UnicodeSecurity.JoinControls do
  @moduledoc false

  alias UnicodeSecurity.Data.Normalization, as: NormalizationData
  alias UnicodeSecurity.Data.{Profile, Scripts}
  alias UnicodeSecurity.Normalization

  # UTS39r34 §3.1.1.1 (https://www.unicode.org/reports/tr39/tr39-34.html):
  # A1 = LJ T* ZWNJ RJ
  # A2 = L M* V M1* ZWNJ M1* L
  # B  = L M* V M1* ZWJ (?!D)
  # L is any Letter; V is CCC9 (including Mc); M is Mn; M1 is Mn/CCC!=0.
  # Each match has one ordinary Script, ignoring Common/Inherited, on NFC.
  # Script_Extensions and scripts outside the match do not participate.
  # Reverse suffix and forward prefix states scan each scalar once. Keeping
  # both L M* and L M* V M1* handles overlapping V candidates without rescans.
  # CCC0 undecomposable joiners survive NFC in order, so pair their decisions
  # with the original joiner indexes rather than normalized scalar positions.

  @spec invalid_indexes([non_neg_integer()]) :: [non_neg_integer()]
  def invalid_indexes(scalars) do
    indexes =
      scalars
      |> Enum.with_index()
      |> Enum.filter(fn {code, _index} -> code in [0x200C, 0x200D] end)
      |> Enum.map(fn {_code, index} -> index end)

    # Pinned canonical decomposition/composition cannot introduce a joiner.
    # With no original joiner there is no context decision to make.
    if indexes == [], do: [], else: invalid_normalized_indexes(scalars, indexes)
  end

  defp invalid_normalized_indexes(scalars, indexes) do
    scalars
    |> Normalization.nfc_scalars()
    |> Enum.map(&properties/1)
    |> Enum.reverse()
    |> Enum.map_reduce({nil, nil, false}, &suffix/2)
    |> elem(0)
    |> Enum.reverse()
    |> scan(indexes, {nil, nil, nil}, [])
  end

  defp properties(code) do
    category = Profile.category(code)
    ccc = NormalizationData.combining_class(code)
    script = Scripts.script(code)

    %{
      code: code,
      script: {:ok, if(script in [:common, :inherited], do: :neutral, else: script)},
      letter: category in [:lu, :ll, :lt, :lm, :lo],
      mark: category == :mn,
      mark1: category == :mn and ccc != 0,
      virama: ccc == 9,
      joining: Profile.joining_type(code),
      vowel: Profile.vowel_dependent?(code)
    }
  end

  # Cache contexts starting immediately AFTER each scalar. A1's right
  # character is immediate; only A2 permits an M1* suffix before its Letter.
  defp suffix(property, {_cursive, conjunct, _vowel} = after_context) do
    next_conjunct =
      cond do
        property.letter -> property.script
        property.mark1 -> merge_scripts(property.script, conjunct)
        true -> nil
      end

    next_cursive = if property.joining in [:r, :d], do: property.script
    {{property, after_context}, {next_cursive, next_conjunct, property.vowel}}
  end

  defp scan([], [], _prefix, invalid), do: Enum.reverse(invalid)

  defp scan([{property, after_context} | rest], indexes, prefix, invalid) do
    {indexes, invalid} = decision(property.code, after_context, prefix, indexes, invalid)
    scan(rest, indexes, advance(property, prefix), invalid)
  end

  defp decision(code, after_context, prefix, [index | indexes], invalid)
       when code in [0x200C, 0x200D] do
    invalid = if valid?(code, prefix, after_context), do: invalid, else: [index | invalid]
    {indexes, invalid}
  end

  defp decision(_code, _after_context, _prefix, indexes, invalid), do: {indexes, invalid}

  defp valid?(0x200C, {cursive, _marks, virama}, {right, conjunct, _vowel}) do
    merge_scripts(cursive, right) != nil or merge_scripts(virama, conjunct) != nil
  end

  defp valid?(0x200D, {_cursive, _marks, virama}, {_right, _conjunct, vowel}) do
    virama != nil and not vowel
  end

  defp advance(property, {cursive, marks, virama}) do
    next_cursive =
      case property.joining do
        joining when joining in [:l, :d] -> property.script
        :t -> merge_scripts(cursive, property.script)
        _joining -> nil
      end

    {next_cursive, advance_marks(property, marks), advance_virama(property, marks, virama)}
  end

  defp advance_marks(property, marks) do
    cond do
      property.letter -> property.script
      property.mark -> merge_scripts(marks, property.script)
      true -> nil
    end
  end

  defp advance_virama(property, marks, virama) do
    cond do
      property.virama and marks != nil -> merge_scripts(marks, property.script)
      property.mark1 -> merge_scripts(virama, property.script)
      true -> nil
    end
  end

  # nil denotes no match; {:ok, :neutral} denotes a match with no ordinary
  # script yet. These must stay distinct for Common/Inherited-only matches.
  defp merge_scripts(nil, _right), do: nil
  defp merge_scripts(_left, nil), do: nil
  defp merge_scripts({:ok, :neutral}, right), do: right
  defp merge_scripts(left, {:ok, :neutral}), do: left
  defp merge_scripts({:ok, script} = left, {:ok, script}), do: left
  defp merge_scripts(_left, _right), do: nil
end
