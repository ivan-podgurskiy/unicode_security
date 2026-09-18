defmodule UnicodeSecurity.MetadataTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Test.ElixirRunner
  alias UnicodeSecurity.UnicodeData.Source

  # Catches public metadata drifting from the pinned source declarations or lock.
  test "exposes complete, portable draft provenance matching the source lock" do
    assert UnicodeSecurity.unicode_version() == "18.0.0"
    assert UnicodeSecurity.uts39_revision() == 34

    manifest = UnicodeSecurity.data_manifest()
    assert manifest.release_status == :draft

    {lock, []} = Code.eval_file("priv/unicode/sources.lock")
    declarations = Enum.sort_by(Source.sources(), & &1.name)
    assert Enum.map(manifest.sources, & &1.name) == Enum.map(declarations, & &1.name)

    Enum.zip(manifest.sources, declarations)
    |> Enum.each(fn {source, declaration} ->
      assert source == Map.merge(declaration, Map.fetch!(lock, declaration.name))
      assert source.version == "18.0.0"
      assert source.status == :draft
      assert source.bytes > 0
      assert source.sha256 =~ ~r/\A[0-9a-f]{64}\z/
      assert Enum.sort(Map.keys(source)) == [:bytes, :name, :sha256, :status, :url, :version]
    end)

    refute inspect(manifest) =~ "/Users/"
  end

  # A consumer must need only compiled runtime modules, without raw source files.
  test "metadata works in an isolated runtime without the source tree" do
    beam_directory = Application.app_dir(:unicode_security, "ebin")

    verification = """
    "18.0.0" = UnicodeSecurity.unicode_version()
    34 = UnicodeSecurity.uts39_revision()
    :lu = UnicodeSecurity.Data.Profile.category(?A)
    :d = UnicodeSecurity.Data.Profile.joining_type(0x628)
    [0xE9] = UnicodeSecurity.Normalization.nfc_scalars([?e, 0x301])
    %{release_status: :draft, sources: sources} = UnicodeSecurity.data_manifest()
    19 = length(sources)
    %{__struct__: UnicodeSecurity.Result,verdict: :safe, skeleton: "rn", reasons: []} =
      UnicodeSecurity.check("m", type: :username)
    %{__struct__: UnicodeSecurity.Result,verdict: :dangerous, valid_input?: false,
      reasons: [%{__struct__: UnicodeSecurity.Reason,code: :invalid_utf8, details: %{invalid_byte: 255}}]} =
      UnicodeSecurity.check(<<255>>, type: :tenant_slug)
    %{__struct__: UnicodeSecurity.Result,policy: :permissive, verdict: :suspicious} =
      UnicodeSecurity.check("Acme & Co.", type: :organization_name)
    false = Code.ensure_loaded?(UnicodeSecurity.UnicodeData.Source)
    """

    # Load only the runtime BEAMs; dev modules sharing the build directory stay inaccessible.
    runtime_beams =
      for module <- [
            UnicodeSecurity,
            UnicodeSecurity.Data.Manifest,
            UnicodeSecurity.Data.Profile,
            UnicodeSecurity.Data.Composition,
            UnicodeSecurity.Data.Normalization,
            UnicodeSecurity.Normalization,
            UnicodeSecurity.Result,
            UnicodeSecurity.Reason,
            UnicodeSecurity.Check,
            UnicodeSecurity.Policy,
            UnicodeSecurity.Profile,
            UnicodeSecurity.JoinControls,
            UnicodeSecurity.Utf8,
            UnicodeSecurity.InvalidInputError,
            UnicodeSecurity.Identifier,
            UnicodeSecurity.Restrictions,
            UnicodeSecurity.Scripts,
            UnicodeSecurity.Confusables,
            UnicodeSecurity.Bidi,
            UnicodeSecurity.Bidi.Explicit,
            UnicodeSecurity.Bidi.Weak,
            UnicodeSecurity.Bidi.Brackets,
            UnicodeSecurity.Data.Bidi,
            UnicodeSecurity.Data.Identifier,
            UnicodeSecurity.Data.Numbers,
            UnicodeSecurity.Data.Scripts,
            UnicodeSecurity.Data.Confusables
          ] do
        Path.join(beam_directory, Atom.to_string(module) <> ".beam")
      end

    loader =
      Enum.map_join(runtime_beams, "\n", fn path ->
        ":code.load_abs(String.to_charlist(#{inspect(Path.rootname(path))}))"
      end)

    assert {"", 0} =
             ElixirRunner.run(loader <> "\n" <> verification, cd: System.tmp_dir!())
  end
end
