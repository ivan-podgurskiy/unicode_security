defmodule UnicodeSecurity.SourceTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Source

  test "locks and verifies source bytes" do
    directory =
      Path.join(
        System.tmp_dir!(),
        "unicode-security-source-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "sample.txt"), "Version: 18.0.0\n0041; 0061\n")

    declarations = [%{name: "sample.txt", version: "18.0.0", status: :draft}]
    lock = Source.lock!(declarations, directory)

    assert :ok = Source.verify!(declarations, directory, lock)
    assert lock["sample.txt"].bytes == 27
    assert byte_size(lock["sample.txt"].sha256) == 64
  end

  test "rejects changed source bytes" do
    directory =
      Path.join(
        System.tmp_dir!(),
        "unicode-security-source-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(directory)
    path = Path.join(directory, "sample.txt")
    File.write!(path, "Version: 18.0.0\n")
    declarations = [%{name: "sample.txt", version: "18.0.0", status: :draft}]
    lock = Source.lock!(declarations, directory)
    File.write!(path, "Version: 18.0.1\n")

    assert_raise ArgumentError, ~r/SHA-256 mismatch for sample.txt/, fn ->
      Source.verify!(declarations, directory, lock)
    end
  end

  test "keeps the complete existing directory when acquisition fails" do
    {:ok, _applications} = Application.ensure_all_started(:inets)

    directory =
      Path.join(
        System.tmp_dir!(),
        "unicode-security-source-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "existing.txt"), "keep me")

    declarations = [
      %{
        name: "sample.txt",
        url: "http://127.0.0.1:1/sample.txt",
        version: "18.0.0",
        status: :draft
      }
    ]

    assert_raise RuntimeError, fn ->
      Source.fetch!(declarations, directory)
    end

    assert File.ls!(directory) == ["existing.txt"]
    assert File.read!(Path.join(directory, "existing.txt")) == "keep me"
  end
end
