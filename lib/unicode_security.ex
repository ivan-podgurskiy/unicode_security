defmodule UnicodeSecurity do
  @moduledoc """
  Unicode identifier security primitives backed by pinned Unicode data.

  Provides `skeleton/1`, script and identifier-property detection, and compiled-data
  metadata. A skeleton is a comparison key only. It must never serve as a canonical
  identifier, replacement value, or authorization decision. Matching keys do not
  establish identity or intent.

  Unicode 18.0.0 data is **draft**, so this milestone is not ready for publication.
  See `data_manifest/0` for pinned source hashes and status. Runtime calls use only
  compiled data, with no file or network access or application processes.
  """

  @doc "Returns the Unicode version used by the compiled data; see `data_manifest/0` for draft status."
  @spec unicode_version() :: binary()
  def unicode_version, do: "18.0.0"

  @doc "Returns the UTS #39 revision targeted by this milestone's skeleton implementation."
  @spec uts39_revision() :: non_neg_integer()
  def uts39_revision, do: 34

  @doc """
  Returns the provenance of the compiled Unicode data.

  The manifest includes the release status and each source's logical filename,
  URL, version, byte size, SHA-256 digest, and status. Unicode 18.0.0 sources are
  currently draft data, which prevents publication. This function performs no
  file or network access.
  """
  @spec data_manifest() :: map()
  defdelegate data_manifest(), to: UnicodeSecurity.Data.Manifest, as: :get

  @doc """
  Returns the UTS #39 confusable skeleton using the pinned Unicode data.

  The result is a comparison key only; do not use it as a canonical identifier,
  display value, replacement for the original input, or authorization decision.
  This milestone uses draft data and is not ready for publication.

  UTS #39 revision 34 defines this as `bidiSkeleton(LTR, input)`. It first applies
  the pinned Unicode Bidirectional Algorithm in isolation at paragraph level 0,
  including combining-mark placement and character-based mirroring. It then
  applies NFD, removes default-ignorable characters, maps MA prototypes, and
  reapplies NFD. It performs no case folding. ASCII characters can also map.

  Each Unicode paragraph is treated as one line, without layout-dependent
  wrapping. X9 boundary neutrals and formatting controls are removed. Mirrored
  characters with no encoded mirror counterpart retain their code point.
  Skeletons of arbitrary bidirectional strings need not be idempotent.

  Accepts a UTF-8 binary of at most 4,096 bytes. Raises `ArgumentError` for
  nonbinary input and `UnicodeSecurity.InvalidInputError` for malformed UTF-8
  or oversized input. The returned skeleton may exceed the input byte limit.

  ## Examples

      iex> UnicodeSecurity.skeleton("pаypаl")
      "paypal"

      iex> UnicodeSecurity.skeleton("m")
      "rn"
  """
  @spec skeleton(binary()) :: binary()
  defdelegate skeleton(input), to: UnicodeSecurity.Confusables

  @doc """
  Returns the sorted unique Script property values observed in the original input.

  Values are lowercase snake-case atoms from the pinned Unicode data, including
  `:common`, `:inherited`, and `:unknown`. This reports ordinary Script properties;
  use `mixed_script?/1` for UTS #39 detection with Script_Extensions.

  Accepts a UTF-8 binary of at most 4,096 bytes. Raises `ArgumentError` for
  nonbinary input and `UnicodeSecurity.InvalidInputError` for malformed UTF-8
  or oversized input, with offsets in the original input.

  ## Examples

      iex> UnicodeSecurity.scripts("раypal")
      [:cyrillic, :latin]

      iex> UnicodeSecurity.scripts("a \\u0301")
      [:common, :inherited, :latin]
  """
  @spec scripts(binary()) :: [atom()]
  defdelegate scripts(input), to: UnicodeSecurity.Scripts

  @doc """
  Detects mixed scripts using UTS #39 revision 34, section 5.1.

  Intersects augmented Script_Extensions sets, including the Han/Latin,
  Japanese, Korean, and Han/Bopomofo combinations. Common and Inherited
  extension values are neutral. Empty and wholly neutral inputs return `false`.
  This is a script test, not an identifier validity or authorization decision.

  Accepts a UTF-8 binary of at most 4,096 bytes, with the same errors and original
  input offsets as `scripts/1`.

  ## Examples

      iex> UnicodeSecurity.mixed_script?("раypal")
      true

      iex> UnicodeSecurity.mixed_script?("ねガ")
      false
  """
  @spec mixed_script?(binary()) :: boolean()
  defdelegate mixed_script?(input), to: UnicodeSecurity.Scripts

  @doc """
  Returns the exact pinned UTS #39 Identifier_Status value for a Unicode scalar.

  This scalar property is not canonically closed. A scalar with status `:restricted`
  can still occur in a string accepted by `allowed_identifier?/1` when a canonically
  equivalent representation consists entirely of Allowed characters.

  Raises `ArgumentError` unless the input is an integer Unicode scalar value.
  """
  @spec identifier_status(integer()) :: :allowed | :restricted
  defdelegate identifier_status(code), to: UnicodeSecurity.Identifier, as: :status

  @doc """
  Returns the sorted exact pinned UTS #39 Identifier_Type set for a Unicode scalar.

  Values are lowercase snake-case atoms from a closed set. Unassigned scalars default
  to `[:not_character]`, as declared by the pinned data. Raises `ArgumentError` unless
  the input is an integer Unicode scalar value.
  """
  @spec identifier_types(integer()) :: [atom()]
  defdelegate identifier_types(code), to: UnicodeSecurity.Identifier, as: :types

  @doc """
  Returns whether a string belongs to the canonically closed UTS #39 General Security Profile.

  Membership permits the input when some canonically equivalent representation consists
  entirely of characters whose Identifier_Status is Allowed. It does not add application
  syntax exceptions, validate identifier grammar, or make a safety or authorization verdict.
  Empty input is vacuously allowed.

  Accepts a UTF-8 binary of at most 4,096 bytes. Raises `ArgumentError` for nonbinary input
  and `UnicodeSecurity.InvalidInputError` for malformed UTF-8 or oversized input, with
  offsets in the original input.

  ## Examples

      iex> UnicodeSecurity.allowed_identifier?("paypal")
      true

      iex> UnicodeSecurity.allowed_identifier?("pay\\u200Dpal")
      false
  """
  @spec allowed_identifier?(binary()) :: boolean()
  defdelegate allowed_identifier?(input), to: UnicodeSecurity.Identifier, as: :allowed?
end
