defmodule UnicodeSecurity.ReleaseDataTest do
  use ExUnit.Case, async: true

  test "records the final Unicode 18 source transition and its single comment-only delta" do
    {report, []} = Code.eval_file("priv/unicode/18.0.0-release.term")
    {lock, []} = Code.eval_file("priv/unicode/sources.lock")

    assert Map.keys(report) |> Enum.sort() ==
             Enum.sort([
               :version,
               :from_status,
               :to_status,
               :sources,
               :generated_runtime_changes,
               :public_behavior_changed?,
               :conflict_keys_changed?
             ])

    assert report.version == "18.0.0"
    assert report.from_status == :draft
    assert report.to_status == :final
    assert report.generated_runtime_changes == ["manifest.ex"]
    assert report.public_behavior_changed? == false
    assert report.conflict_keys_changed? == false
    assert length(report.sources) == 21
    assert Enum.map(report.sources, & &1.name) == Enum.sort(Map.keys(lock))
    assert Enum.count(report.sources, &(&1.classification == :comments_only)) == 1
    assert Enum.count(report.sources, &(&1.classification == :identical)) == 20

    bidi = Enum.find(report.sources, &(&1.name == "BidiMirroring.txt"))
    assert bidi.classification == :comments_only
    assert bidi.changed? == true

    assert bidi.before == %{
             bytes: 27352,
             sha256: "cd47918b28b73c3be37d730d0f48ab11e862afef9eb11d85ad832be9fb6c7f8f"
           }

    assert bidi.after == %{
             bytes: 27294,
             sha256: "cd54810ebf52f0e61a730c8b9cb25975de6c85f6d788a559b416afd548923fd6"
           }

    for source <- report.sources do
      assert Map.keys(source) |> Enum.sort() ==
               Enum.sort([:name, :before, :after, :changed?, :classification])

      assert Map.keys(source.before) |> Enum.sort() == [:bytes, :sha256]
      assert Map.keys(source.after) |> Enum.sort() == [:bytes, :sha256]
      assert source.after == Map.fetch!(lock, source.name)
      assert is_boolean(source.changed?)
      assert source.changed? == (source.classification == :comments_only)

      if source.classification == :identical do
        assert source.before == source.after
      end
    end
  end
end
