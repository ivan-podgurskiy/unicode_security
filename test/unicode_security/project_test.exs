defmodule UnicodeSecurity.ProjectTest do
  use ExUnit.Case, async: true

  test "publishes the PRD package contract" do
    project = UnicodeSecurity.MixProject.project()
    package = project[:package]

    assert project[:app] == :unicode_security
    assert project[:version] == "0.1.0"
    assert project[:elixir] == "~> 1.14"
    assert package[:licenses] == ["MIT"]
    assert package[:maintainers] == ["Ivan Podgurskiy"]
    assert Code.ensure_loaded?(UnicodeSecurity)
    refute function_exported?(UnicodeSecurity.Application, :start, 2)
  end
end
