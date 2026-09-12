defmodule UnicodeSecurity do
  @moduledoc """
  Unicode identifier security primitives backed by pinned Unicode data.

  Milestone 0 provides `skeleton/1` and compiled-data metadata. A skeleton is a
  comparison key only. It must never serve as a canonical identifier, replacement
  value, or authorization decision. Matching keys do not establish identity or intent.

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

  The algorithm applies pinned NFD, one confusables mapping pass, and pinned NFD
  again. It performs no case folding. ASCII characters can also have mappings.

  Accepts a UTF-8 binary of at most 4,096 bytes. Raises `ArgumentError` for
  nonbinary input and `UnicodeSecurity.InvalidInputError` for malformed UTF-8
  or oversized input. The returned skeleton may exceed the input byte limit.
  """
  @spec skeleton(binary()) :: binary()
  defdelegate skeleton(input), to: UnicodeSecurity.Confusables
end
