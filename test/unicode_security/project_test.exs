defmodule UnicodeSecurity.ProjectTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Source

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

    for name <-
          ~w(bidi composition confusables identifier manifest normalization numbers profile scripts) do
      assert "lib/unicode_security/data/#{name}.ex" in packaged
    end

    for path <- packaged do
      assert String.starts_with?(path, "lib/") or
               path in ~w(.formatter.exs mix.exs README.md LICENSE CHANGELOG.md THIRD_PARTY_NOTICES.md)

      refute path =~ ~r{(^|/)(priv|dev|scripts|bench|test|\.superpowers|docs/superpowers)(/|$)}
      refute path =~ ~r{PRD|research|AGENTS|(?:-plan|-design)\.md}
    end
  end

  test "publishes the final-data quality and public documentation contract" do
    workflow = File.read!(".github/workflows/ci.yml")

    generated_data_check =
      "      - if: matrix.quality\n        run: mix run scripts/check_generated.exs"

    release_data_check =
      "      - if: matrix.quality\n        run: mix run scripts/check_release_data.exs"

    assert String.contains?(workflow, generated_data_check)
    assert String.contains?(workflow, release_data_check)

    {generated_index, _} = :binary.match(workflow, generated_data_check)
    {release_index, _} = :binary.match(workflow, release_data_check)
    assert generated_index < release_index

    {:docs_v1, _, _, _, module_doc, _, docs} = Code.fetch_docs(UnicodeSecurity)

    assert module_doc |> doc_text() |> String.contains?("Unicode 18.0.0 data is **final**")

    data_manifest_doc =
      Enum.find_value(docs, fn
        {{:function, :data_manifest, 0}, _, _, doc, _} -> doc_text(doc)
        _ -> nil
      end)

    assert data_manifest_doc
    assert data_manifest_doc =~ "final"
    refute data_manifest_doc =~ "draft"
  end

  test "exports skeleton, metadata and script detection" do
    assert Code.ensure_loaded?(UnicodeSecurity)

    for {name, arity} <- [
          check: 2,
          audit: 2,
          check_many: 2,
          identifier_status: 1,
          identifier_types: 1,
          allowed_identifier?: 1,
          skeleton: 1,
          same_skeleton?: 2,
          confusable?: 2,
          compare: 2,
          compare: 3,
          conflict_key: 2,
          conflicts?: 3,
          conflicts: 3,
          scripts: 1,
          mixed_script?: 1,
          mixed_number?: 1,
          restriction_level: 1,
          unicode_version: 0,
          uts39_revision: 0,
          data_manifest: 0
        ] do
      assert function_exported?(UnicodeSecurity, name, arity)
    end
  end

  test "Windows checkout preserves the exact bytes of vendored Unicode inputs" do
    source_directory = Source.directory(File.cwd!()) |> Path.relative_to(File.cwd!())

    assert_checkout_bytes(
      Path.wildcard(Path.join(source_directory, "*")) ++
        ["priv/unicode/sources.lock", "priv/unicode/18.0.0-release.term"]
    )
  end

  test "Windows checkout preserves LF bytes of generated runtime modules" do
    assert_checkout_bytes(Path.wildcard("lib/unicode_security/data/*.ex"))
  end

  defp assert_checkout_bytes(paths) do
    assert paths != []
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    directory = Path.join(System.tmp_dir!(), "unicode-security-checkout-#{suffix}")
    on_exit(fn -> File.rm_rf!(directory) end)
    assert {"", 0} = System.cmd("git", ["init", "--quiet", directory], stderr_to_stdout: true)

    if File.regular?(".gitattributes") do
      File.cp!(".gitattributes", Path.join(directory, ".gitattributes"))
    end

    for path <- paths do
      File.mkdir_p!(Path.dirname(Path.join(directory, path)))
      File.cp!(path, Path.join(directory, path))
      original = File.read!(path)

      assert {object, 0} =
               System.cmd("git", ["hash-object", "-w", "--no-filters", path], cd: directory)

      assert {checkout, 0} =
               System.cmd(
                 "git",
                 [
                   "-c",
                   "core.autocrlf=true",
                   "cat-file",
                   "--filters",
                   "--path=#{path}",
                   String.trim(object)
                 ],
                 cd: directory
               )

      assert :crypto.hash(:sha256, checkout) == :crypto.hash(:sha256, original),
             "Windows checkout changed the pinned bytes of #{path}"
    end
  end

  defp doc_text(%{"en" => text}), do: text
  defp doc_text(text) when is_binary(text), do: text
end
