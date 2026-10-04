defmodule UnicodeSecurity.DomainResult do
  @moduledoc """
  IDNA forms and original-label analysis for an explicit domain check.

  `unicode` and `ascii` are whole-name U-label and A-label forms, including an
  optional final root dot. They are `nil` after any hostname validity failure,
  while `labels` retains independently safe partial results. `mapped?` reports
  whether the whole Unicode form differs from original input. `valid_idna?`
  includes IDNA rules, DNS lengths, and public hostname restrictions.
  `uts46_revision` identifies the pinned nontransitional processing rules.
  """
  defstruct [
    :unicode,
    :ascii,
    :trailing_dot?,
    :mapped?,
    :valid_idna?,
    uts46_revision: 36,
    labels: []
  ]

  @type t :: %__MODULE__{
          unicode: binary() | nil,
          ascii: binary() | nil,
          labels: [UnicodeSecurity.DomainLabel.t()],
          trailing_dot?: boolean() | nil,
          mapped?: boolean() | nil,
          valid_idna?: boolean() | nil,
          uts46_revision: 36
        }
end
