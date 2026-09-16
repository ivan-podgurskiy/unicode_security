defmodule UnicodeSecurity.Restrictions do
  @moduledoc false

  alias UnicodeSecurity.Data.Numbers
  alias UnicodeSecurity.Identifier
  alias UnicodeSecurity.Scripts
  alias UnicodeSecurity.Utf8

  # Frozen UAX #31 revision 44 (Unicode 18.0.0 proposed), Table 5:
  # https://www.unicode.org/reports/tr31/tr31-44.html#Table_Recommended_Scripts
  # All 30 entries, including Common/Inherited; Bopomofo moved to Limited Use
  # in Unicode 17 and is NOT Recommended. No host Unicode/property lookup.
  @recommended MapSet.new([
                 :common,
                 :inherited,
                 :arabic,
                 :armenian,
                 :bengali,
                 :cyrillic,
                 :devanagari,
                 :ethiopic,
                 :georgian,
                 :greek,
                 :gujarati,
                 :gurmukhi,
                 :hangul,
                 :han,
                 :hebrew,
                 :hiragana,
                 :katakana,
                 :kannada,
                 :khmer,
                 :lao,
                 :latin,
                 :malayalam,
                 :myanmar,
                 :oriya,
                 :sinhala,
                 :tamil,
                 :telugu,
                 :thaana,
                 :thai,
                 :tibetan
               ])
  @moderate @recommended |> MapSet.delete(:cyrillic) |> MapSet.delete(:greek)
  @cjk MapSet.new([:kore, :hanb, :jpan])

  @type level ::
          :ascii
          | :single_script_restrictive
          | :highly_restrictive
          | :moderately_restrictive
          | :minimally_restrictive
          | :unrestricted

  @spec mixed_number?(binary()) :: boolean()
  def mixed_number?(input) do
    input
    |> Utf8.decode!()
    |> Enum.map(fn {code, _offset} -> Numbers.zero(code) end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> length()
    |> Kernel.>(1)
  end

  # UTS #39 revision 34 section 5.2, using the canonically closed General
  # Security Profile from section 3.1. Grammar/policy belongs to callers.
  @spec restriction_level(binary()) :: level()
  def restriction_level(input) do
    scalars = input |> Utf8.decode!() |> Enum.map(&elem(&1, 0))

    cond do
      not Identifier.allowed_scalars?(scalars) -> :unrestricted
      Enum.all?(scalars, &(&1 <= 0x7F)) -> :ascii
      nonempty?(Scripts.resolved_set(scalars)) -> :single_script_restrictive
      true -> mixed_level(Scripts.resolved_without_latin(scalars))
    end
  end

  defp mixed_level(resolved) do
    # The original empty intersection implies at least one entry does not
    # contain Latin, so the reduced intersection here cannot be ALL.
    cond do
      not MapSet.disjoint?(resolved, @cjk) -> :highly_restrictive
      not MapSet.disjoint?(resolved, @moderate) -> :moderately_restrictive
      true -> :minimally_restrictive
    end
  end

  defp nonempty?(:all), do: true
  defp nonempty?(resolved), do: MapSet.size(resolved) > 0
end
