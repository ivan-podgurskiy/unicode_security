defmodule UnicodeSecurity.Collision do
  @moduledoc """
  Ordered valid binary inputs sharing one computed skeleton key.

  A collision requires at least two distinct exact binary inputs. Its class is
  the highest-precedence primary confusable class realized by a pair of
  canonically distinct inputs, or `:none` when distinct inputs share only a
  canonical form. Domain classes use changed Unicode labels and the strongest
  changed-label class of each pair.
  """

  alias UnicodeSecurity.Reason

  @type class :: :mixed_script_confusable | :whole_script_confusable | :single_script_confusable

  defstruct [:key, :class, :unicode_version, indexes: [], inputs: [], classes: [], reasons: []]

  @type t :: %__MODULE__{
          key: binary() | nil,
          indexes: [non_neg_integer()],
          inputs: [binary()],
          class: class() | :none | nil,
          classes: [class()],
          reasons: [Reason.t()],
          unicode_version: binary() | nil
        }
end
