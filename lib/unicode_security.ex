defmodule UnicodeSecurity do
  @moduledoc """
  Unicode identifier security primitives backed by pinned Unicode data.

  A skeleton is a comparison key, not a canonical identifier or replacement value.
  """

  @doc "Returns the Unicode version used by the compiled data."
  @spec unicode_version() :: binary()
  def unicode_version, do: "18.0.0"

  @doc "Returns the UTS #39 revision implemented by this release."
  @spec uts39_revision() :: non_neg_integer()
  def uts39_revision, do: 34

  @doc """
  Returns the provenance of the compiled Unicode data.

  The manifest includes the release status and each source's logical filename,
  URL, version, byte size, SHA-256 digest, and status. Unicode 18.0.0 sources are
  currently draft data. This function performs no file or network access.
  """
  @spec data_manifest() :: map()
  defdelegate data_manifest(), to: UnicodeSecurity.Data.Manifest, as: :get

  @doc """
  Returns the UTS #39 confusable skeleton using the pinned Unicode data.

  The result is a comparison key only; do not use it as a canonical identifier,
  display value, or replacement for the original input.

  Accepts a UTF-8 binary of at most 4,096 bytes. Raises `ArgumentError` for
  nonbinary input and `UnicodeSecurity.InvalidInputError` for malformed UTF-8
  or oversized input. The returned skeleton may exceed the input byte limit.
  """
  @spec skeleton(binary()) :: binary()
  defdelegate skeleton(input), to: UnicodeSecurity.Confusables
end
