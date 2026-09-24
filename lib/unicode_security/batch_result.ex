defmodule UnicodeSecurity.BatchResult do
  @moduledoc """
  Eager audit results with ordered duplicate and skeleton-collision groups.

  Collection findings describe relationships between inputs. They do not change
  any individual item's result or verdict.
  """

  alias UnicodeSecurity.{BatchItem, Collision, Duplicate}

  defstruct results: [], collisions: [], duplicates: [], unicode_version: nil

  @type t :: %__MODULE__{
          results: [BatchItem.t()],
          collisions: [Collision.t()],
          duplicates: [Duplicate.t()],
          unicode_version: binary() | nil
        }
end
