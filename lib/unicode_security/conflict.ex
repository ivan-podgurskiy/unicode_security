defmodule UnicodeSecurity.Conflict do
  @moduledoc """
  One existing identifier whose pinned skeleton equals the candidate's key.

  `index` is the zero-based position in the supplied enumerable. `code` distinguishes
  exact original bytes, nonconfusable skeleton collisions (including IDNA-equivalent
  domain spellings), and the three confusable classes. `comparison` retains
  original-input facts and both sides'
  mapping evidence. A conflict is advisory; it does not establish ownership,
  impersonation, identifier validity, or an authorization decision.
  """

  defstruct [:input, :existing, :index, :key, :comparison, :code, :unicode_version]

  @type code ::
          :exact_duplicate
          | :skeleton_collision
          | :single_script_confusable
          | :whole_script_confusable
          | :mixed_script_confusable

  @type t :: %__MODULE__{
          input: binary(),
          existing: binary(),
          index: non_neg_integer(),
          key: binary(),
          comparison: UnicodeSecurity.Comparison.t(),
          code: code(),
          unicode_version: binary()
        }
end
