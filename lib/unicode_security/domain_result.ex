defmodule UnicodeSecurity.DomainResult do
  @moduledoc "IDNA forms and original-label analysis for an explicit domain check."
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
