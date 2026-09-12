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

  test "packages every runtime module and only distributable project files" do
    files = UnicodeSecurity.MixProject.project()[:package][:files]
    assert "lib" in files

    packaged =
      Enum.flat_map(files, fn path ->
        if File.dir?(path), do: Path.wildcard(path <> "/**/*"), else: Path.wildcard(path)
      end)
      |> Enum.reject(&File.dir?/1)

    for path <- Path.wildcard("lib/**/*.ex") do
      assert path in packaged
    end

    for name <- ~w(confusables manifest normalization) do
      assert "lib/unicode_security/data/#{name}.ex" in packaged
    end

    for path <- packaged do
      assert String.starts_with?(path, "lib/") or
               path in ~w(.formatter.exs mix.exs README.md LICENSE CHANGELOG.md THIRD_PARTY_NOTICES.md)

      refute path =~ ~r{(^|/)(priv|dev|scripts|bench|test|\.superpowers|docs/superpowers)(/|$)}
      refute path =~ ~r{PRD|research|AGENTS|(?:-plan|-design)\.md}
    end
  end

  test "exports the complete Milestone 0 public interface" do
    assert Code.ensure_loaded?(UnicodeSecurity)

    for {name, arity} <- [skeleton: 1, unicode_version: 0, uts39_revision: 0, data_manifest: 0] do
      assert function_exported?(UnicodeSecurity, name, arity)
    end
  end
end
