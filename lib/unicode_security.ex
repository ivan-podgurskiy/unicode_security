defmodule UnicodeSecurity do
  @moduledoc """
  Unicode identifier security primitives backed by pinned Unicode data.

  Provides `skeleton/1`, script, number, and restriction-level detection, identifier
  properties, `check/2` policy Results/Reasons for three profiles, and compiled-data
  metadata. A skeleton is a comparison key only. It must never serve as a canonical
  identifier, replacement value, or authorization decision. Matching keys do not
  establish identity or intent.

  Unicode 18.0.0 data is **draft**, so this milestone is not ready for publication.
  See `data_manifest/0` for pinned source hashes and status. Runtime calls use only
  compiled data, with no file or network access or application processes.
  """

  @type restriction_level ::
          :ascii
          | :single_script_restrictive
          | :highly_restrictive
          | :moderately_restrictive
          | :minimally_restrictive
          | :unrestricted

  @doc """
  Analyzes an identifier and returns original-input facts and policy findings.

  Requires `type: :username`, `:tenant_slug`, or `:organization_name`; domains
  are not supported in this milestone. `policy` selects `:strict`, `:default`,
  or `:permissive`. Usernames and tenant slugs default to `:default`;
  organization names default to `:permissive`. Optional `allowed_scripts` and
  `denied_scripts` accept ordinary script atoms from the pinned data. An omitted
  allowlist permits all scripts; an explicit empty list permits neutral scalars
  only. Multivalued Script_Extensions pass if a permitted candidate survives.

  Username syntax accepts letters, marks, decimal digits and ASCII `_-.`;
  tenant slugs accept the same categories with only `-` punctuation. Organization
  names additionally accept pinned whitespace and punctuation categories.
  There are no first-character rules. Join controls receive normative context
  checks. Input is preserved without trimming, folding or rewriting.

  Raw restriction facts remain unchanged. Restricted-character findings report
  original raw scalars independently of canonical membership, except username
  `_-.` and tenant `-`. Those exceptions also extend policy membership using
  punctuation-separated runs, preventing composition across separators.
  Organization whitespace and punctuation allowances affect syntax only.

  Every binary with valid configuration returns `UnicodeSecurity.Result`,
  including empty, malformed UTF-8 and input over 4,096 original bytes. Partial
  results retain `nil` facts. Empty input is fully analyzed with a high-severity
  finding. Positions are original zero-based byte/scalar indexes; global
  findings follow positional findings. Reasons sort by original byte offset, code,
  and deterministic details. See `UnicodeSecurity.Reason` for all codes, details
  and severities. The highest severity determines verdict.
  This check does not detect collisions or establish identity or authorization.

  Raises `ArgumentError` for nonbinary input or invalid configuration, including
  missing type, duplicate/unknown options, malformed script lists and overlapping
  allow/deny lists. Configuration is validated before content analysis.

  ## Examples

      iex> UnicodeSecurity.check("alice-smith", type: :username).verdict
      :safe

      iex> UnicodeSecurity.check("", type: :username).verdict
      :dangerous
  """
  @spec check(binary(), keyword()) :: UnicodeSecurity.Result.t()
  defdelegate check(input, options), to: UnicodeSecurity.Check

  @doc """
  Lazily audits an enumerable of candidate identifiers under one policy.

  Returns a repeatable stream of `UnicodeSecurity.BatchItem` values with
  zero-based indexes and unchanged inputs. Valid options and an enumerable are
  required when this function is called; source items are read only as the
  stream is consumed. Each binary uses the same analysis as `check/2`.
  Nonbinary items become dangerous results with an `:invalid_item_type` reason.
  Producer exceptions propagate during consumption. The stream retains only
  its source and policy between items.
  """
  @spec audit(Enumerable.t(), keyword()) :: Enumerable.t()
  defdelegate audit(enumerable, options), to: UnicodeSecurity.Batch

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
  Returns whether two validated original inputs have equal pinned skeleton keys.

  Both inputs are validated left to right, even when identical. A matching key
  does not establish identity, intent, or authorization.
  """
  @spec same_skeleton?(binary(), binary()) :: boolean()
  defdelegate same_skeleton?(left, right), to: UnicodeSecurity.Pair

  @doc """
  Returns whether two original inputs share a skeleton but differ canonically.

  Canonically equivalent strings, including identical strings, return `false`.
  Both inputs are validated left to right. This predicate is a comparison fact,
  not a safety or authorization verdict.
  """
  @spec confusable?(binary(), binary()) :: boolean()
  defdelegate confusable?(left, right), to: UnicodeSecurity.Pair

  @doc """
  Returns comparison facts and original-input mapping evidence for two identifiers.

  Accepts optional `type: :username`, `:tenant_slug`, or `:organization_name`.
  Both inputs are validated left to right. Matching keys are comparison facts,
  not identity or authorization decisions.
  """
  @spec compare(binary(), binary(), term()) :: UnicodeSecurity.Comparison.t()
  def compare(left, right, options \\ []), do: UnicodeSecurity.Pair.compare(left, right, options)

  @doc """
  Returns the pinned skeleton key for a required identifier type.

  Requires exactly `type: :username`, `:tenant_slug`, or `:organization_name`.
  Policy and script overrides are not accepted. The original UTF-8 input is
  validated with the 4,096-byte limit; there is no case folding, trimming, or
  policy check. The key is only a comparison fact, not a storage or identity key.
  """
  @spec conflict_key(binary(), term()) :: binary()
  defdelegate conflict_key(input, options), to: UnicodeSecurity.Conflicts

  @doc """
  Returns whether any visited existing identifier has the candidate's skeleton.

  Requires exactly the same type option as `conflict_key/2`. Candidate validation
  precedes collection validation. The enumerable is consumed lazily and stops at
  the first match; malformed or nonbinary visited values raise, while unvisited
  values are untouched. This is an advisory check: concurrent storage changes may
  alter the result, and matching does not establish ownership or authorization.
  """
  @spec conflicts?(binary(), Enumerable.t(), term()) :: boolean()
  defdelegate conflicts?(input, existing, options), to: UnicodeSecurity.Conflicts

  @doc """
  Returns all skeleton matches in enumerable order with original indexes and evidence.

  Requires exactly the same type option as `conflict_key/2`. Candidate validation
  precedes collection validation; every existing value is visited, validated as a
  UTF-8 binary of at most 4,096 bytes, and may raise. Duplicates are retained.
  Results are advisory and must be paired with application storage checks; they
  are not policy verdicts or authorization decisions.
  """
  @spec conflicts(binary(), Enumerable.t(), term()) :: [UnicodeSecurity.Conflict.t()]
  defdelegate conflicts(input, existing, options), to: UnicodeSecurity.Conflicts

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

  @doc """
  Detects multiple decimal number systems using UTS #39 revision 34, section 5.3.

  Only Decimal_Number (Nd) scalars contribute a system, identified by their
  pinned zero character. Other numeric characters do not contribute systems;
  this does not validate identifier syntax or profile membership.

  Accepts a UTF-8 binary of at most 4,096 bytes, with the same errors and
  original input offsets as `scripts/1`. Empty input returns `false`.

  ## Examples

      iex> UnicodeSecurity.mixed_number?("123")
      false

      iex> UnicodeSecurity.mixed_number?("1١")
      true
  """
  @spec mixed_number?(binary()) :: boolean()
  defdelegate mixed_number?(input), to: UnicodeSecurity.Restrictions

  @doc """
  Returns the first applicable UTS #39 revision 34, section 5.2 restriction level.

  Ordered levels are `:ascii`, `:single_script_restrictive`, `:highly_restrictive`,
  `:moderately_restrictive`, `:minimally_restrictive`, and `:unrestricted`. The
  canonically closed General Security Profile is tested first: outside-profile
  inputs return `:unrestricted`, even when ASCII or single-script. Empty input
  returns `:ascii`.

  Uses resolved augmented Script_Extensions, not the observed Script values
  returned by `scripts/1`. Recommended scripts are frozen from UAX #31 revision
  44, Table 5 (Unicode 18.0.0 proposed); Bopomofo is Limited Use, not Recommended.
  This primitive adds no syntax rules or policy exceptions and is not a safety
  or authorization decision. Mixed numbers are detected separately.

  Accepts a UTF-8 binary of at most 4,096 bytes, with the same errors and
  original input offsets as `scripts/1`.

  ## Examples

      iex> UnicodeSecurity.restriction_level("paypal")
      :ascii

      iex> UnicodeSecurity.restriction_level("aねガ")
      :highly_restrictive
  """
  @spec restriction_level(binary()) :: restriction_level()
  defdelegate restriction_level(input), to: UnicodeSecurity.Restrictions
end
