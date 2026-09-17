defmodule UnicodeSecurity.SourceTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Source

  test "rejects a malformed surviving lock before writing recovery files" do
    for lock_text <- ["nil", "false", "[]", "123"] do
      root = temporary_directory()
      File.mkdir_p!(root)
      lock_path = Path.join(root, "sources.lock")
      File.write!(lock_path, lock_text)
      directory = Path.join(root, "sources")
      source = %{name: "sample.txt", version: "18.0.0", status: :draft, url: "unused"}

      assert_raise ArgumentError, ~r/source lock must evaluate to a map/, fn ->
        Source.fetch!([source], directory)
      end

      refute File.exists?(directory)
      assert File.read!(lock_path) == lock_text
    end
  end

  test "recovers identical source bytes without rewriting the surviving lock" do
    body = "# Version: 18.0.0\noriginal\n"
    root = temporary_directory()
    directory = Path.join(root, "sources")
    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "sample.txt"), body)
    {url, server} = serve_once(body)
    source = %{unicode_data_source(url) | name: "sample.txt"}
    lock = Source.lock!([source], directory)
    lock_bytes = "# preserve formatting\n" <> inspect(lock) <> "\n"
    File.write!(Path.join(root, "sources.lock"), lock_bytes)
    File.rm_rf!(directory)

    assert Source.fetch!([source], directory) == lock
    Task.await(server)
    assert File.read!(Path.join(directory, "sample.txt")) == body
    assert File.read!(Path.join(root, "sources.lock")) == lock_bytes
  end

  test "permits deliberate update only through the explicit update mode" do
    body = "# Version: 18.0.0\nupdated\n"
    root = temporary_directory()
    directory = Path.join(root, "sources")
    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "sample.txt"), "# Version: 18.0.0\noriginal\n")
    {url, server} = serve_once(body)
    source = %{unicode_data_source(url) | name: "sample.txt"}
    previous = Source.lock!([source], directory)
    File.write!(Path.join(root, "sources.lock"), inspect(previous))

    updated = Source.fetch!([source], directory, :update_lock)
    Task.await(server)
    refute updated == previous
    assert Source.verify!([source], directory, updated) == :ok
    assert File.read!(Path.join(directory, "sample.txt")) == body
  end

  # Breaks: trusting replacement downloads when an authoritative lock survives
  # deletion of the fixture directory. Assert the install boundary and lock bytes.
  test "keeps an existing lock authoritative during recovery of missing fixtures" do
    original = "# Version: 18.0.0\noriginal\n"

    for changed <- ["# Version: 18.0.0\nmodified\n", original <> "extra\n"] do
      root = temporary_directory()
      directory = Path.join(root, "sources")
      File.mkdir_p!(directory)
      File.write!(Path.join(directory, "sample.txt"), original)
      {url, server} = serve_once(changed)
      source = %{unicode_data_source(url) | name: "sample.txt"}
      lock = Source.lock!([source], directory)
      lock_path = Path.join(root, "sources.lock")
      lock_bytes = inspect(lock) <> "\n"
      File.write!(lock_path, lock_bytes)
      File.rm_rf!(directory)

      assert_raise ArgumentError, ~r/(SHA-256|byte-size) mismatch for sample.txt/, fn ->
        Source.fetch!([source], directory)
      end

      Task.await(server)
      refute File.exists?(directory)
      assert File.read!(lock_path) == lock_bytes
      assert File.ls!(root) == ["sources.lock"]
    end
  end

  test "declares exactly four additional official draft Unicode 18 profile sources" do
    sources = Source.sources()
    assert length(sources) == 19

    for {name, suffix} <- [
          {"DerivedNormalizationProps.txt", "DerivedNormalizationProps.txt"},
          {"PropList.txt", "PropList.txt"},
          {"DerivedJoiningType.txt", "extracted/DerivedJoiningType.txt"},
          {"IndicSyllabicCategory.txt", "IndicSyllabicCategory.txt"}
        ] do
      assert %{url: url, version: "18.0.0", status: :draft} =
               Enum.find(sources, &(&1.name == name))

      assert url == "https://www.unicode.org/Public/18.0.0/ucd/" <> suffix
    end

    {lock, []} = Code.eval_file("priv/unicode/sources.lock")
    assert Source.verify!(sources, "priv/unicode/18.0.0-draft", lock) == :ok
  end

  test "locks and verifies source bytes" do
    directory = temporary_directory()

    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "sample.txt"), "Version: 18.0.0\n0041; 0061\n")

    declarations = [%{name: "sample.txt", version: "18.0.0", status: :draft}]
    lock = Source.lock!(declarations, directory)

    assert :ok = Source.verify!(declarations, directory, lock)
    assert lock["sample.txt"].bytes == 27
    assert byte_size(lock["sample.txt"].sha256) == 64
  end

  test "rejects changed source bytes" do
    directory = temporary_directory()

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

    directory = temporary_directory()

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

  test "rejects a malformed semicolon response as UnicodeData" do
    {url, server} = serve_once("error; unavailable")
    directory = temporary_directory()

    assert_raise RuntimeError, ~r/invalid UnicodeData records/, fn ->
      Source.fetch!([unicode_data_source(url)], directory)
    end

    Task.await(server)
    refute File.exists?(directory)
  end

  test "rejects a non-scalar UnicodeData code point" do
    record = "D800;<surrogate>;Cs;0;L;;;;;N;;;;;"
    {url, server} = serve_once(record)
    directory = temporary_directory()

    assert_raise RuntimeError, ~r/invalid UnicodeData records/, fn ->
      Source.fetch!([unicode_data_source(url)], directory)
    end

    Task.await(server)
    refute File.exists?(directory)
  end

  test "rejects a negative UnicodeData mapping code point" do
    record = "0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;-001;"
    {url, server} = serve_once(record)
    directory = temporary_directory()

    assert_raise RuntimeError, ~r/invalid UnicodeData records/, fn ->
      Source.fetch!([unicode_data_source(url)], directory)
    end

    Task.await(server)
    refute File.exists?(directory)
  end

  test "accepts representative UnicodeData records" do
    records =
      "0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;\n" <>
        "00C0;LATIN CAPITAL LETTER A WITH GRAVE;Lu;0;L;0041 0300;;;;N;" <>
        "LATIN CAPITAL LETTER A GRAVE;;;00E0;\n"

    {url, server} = serve_once(records)
    directory = temporary_directory()
    source = unicode_data_source(url)

    lock = Source.fetch!([source], directory)

    Task.await(server)
    assert File.read!(Path.join(directory, "UnicodeData.txt")) == records
    assert :ok = Source.verify!([source], directory, lock)
  end

  test "accepts a structurally paired UnicodeData surrogate range" do
    records =
      "D800;<Non Private Use High Surrogate, First>;Cs;0;L;;;;;N;;;;;\n" <>
        "DB7F;<Non Private Use High Surrogate, Last>;Cs;0;L;;;;;N;;;;;\n"

    {url, server} = serve_once(records)
    directory = temporary_directory()
    source = unicode_data_source(url)

    lock = Source.fetch!([source], directory)

    Task.await(server)
    assert :ok = Source.verify!([source], directory, lock)
  end

  test "keeps the installed directory when backup cleanup fails" do
    directory = temporary_directory()
    staging = temporary_directory()
    File.mkdir_p!(directory)
    File.mkdir_p!(staging)
    File.write!(Path.join(directory, "old-only.txt"), "incomplete")
    File.write!(Path.join(staging, "new-only.txt"), "complete")
    test_process = self()

    cleanup = fn backup ->
      send(test_process, {:cleanup_attempted, backup})
      raise "cleanup failed"
    end

    assert_raise RuntimeError, "cleanup failed", fn ->
      Source.install_staged!(staging, directory, cleanup)
    end

    assert File.ls!(directory) == ["new-only.txt"]
    assert File.read!(Path.join(directory, "new-only.txt")) == "complete"
    refute File.exists?(Path.join(directory, "old-only.txt"))
    assert_receive {:cleanup_attempted, backup}
    assert File.read!(Path.join(backup, "old-only.txt")) == "incomplete"
    on_exit(fn -> File.rm_rf!(backup) end)
  end

  defp temporary_directory do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    directory = Path.join(System.tmp_dir!(), "unicode-security-source-#{suffix}")

    on_exit(fn -> File.rm_rf!(directory) end)
    directory
  end

  defp unicode_data_source(url) do
    %{name: "UnicodeData.txt", url: url, version: "18.0.0", status: :draft}
  end

  test "rejects lock entry mismatch and invalid source declarations before writes" do
    directory = temporary_directory()
    source = %{name: "sample.txt", version: "18.0.0", status: :draft, url: "unused"}
    assert_raise ArgumentError, fn -> Source.verify!([source], directory, %{}) end

    for sources <- [
          [%{source | version: "17.0.0"}],
          [%{source | status: :final}],
          [%{source | name: "../sample.txt"}],
          [source, source],
          [%{source | url: nil}]
        ] do
      assert_raise ArgumentError, fn -> Source.fetch!(sources, directory) end
    end

    refute File.exists?(directory)
  end

  test "restores the previous directory if staged installation fails" do
    directory = temporary_directory()
    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "existing.txt"), "keep")

    assert_raise File.RenameError, fn ->
      Source.install_staged!(directory <> "-missing", directory)
    end

    assert File.read!(Path.join(directory, "existing.txt")) == "keep"
  end

  test "rejects HTTP errors and preserves existing sources" do
    {url, server} = serve_once("not found", "404 Not Found")
    directory = temporary_directory()

    assert_raise RuntimeError, ~r/HTTP 404/, fn ->
      Source.fetch!([unicode_data_source(url)], directory)
    end

    Task.await(server)
    refute File.exists?(directory)
  end

  test "HTTPS acquisition fails closed when the endpoint is unavailable" do
    directory = temporary_directory()
    source = unicode_data_source("https://127.0.0.1:1/18.0.0/ucd/UnicodeData.txt")
    assert_raise RuntimeError, ~r/failed to fetch/, fn -> Source.fetch!([source], directory) end
    refute File.exists?(directory)
  end

  test "checks version headers for security and conformance sources" do
    for body <- ["# Version: 18.0.0\n", "# Version: 17.0.0\n"] do
      {url, server} = serve_once(body)
      source = %{unicode_data_source(url) | name: "confusables.txt"}
      directory = temporary_directory()

      if body == "# Version: 18.0.0\n" do
        lock = Source.fetch!([source], directory)
        assert :ok = Source.verify!([source], directory, lock)
      else
        assert_raise RuntimeError, ~r/version validation failed/, fn ->
          Source.fetch!([source], directory)
        end

        refute File.exists?(directory)
      end

      Task.await(server)
    end
  end

  test "rejects incomplete, mismatched and malformed surrogate sentinels" do
    first = "D800;<High Surrogate, First>;Cs;0;L;;;;;N;;;;;\n"

    for records <- [
          "0041;A",
          first,
          first <> "0041;A;Lu;0;L;;;;;N;;;;;\n",
          first <> "DB7F;<Other Surrogate, Last>;Cs;0;L;;;;;N;;;;;\n",
          "XXXX;<High Surrogate, First>;Cs;0;L;;;;;N;;;;;\n"
        ] do
      {url, server} = serve_once(records)
      directory = temporary_directory()

      assert_raise RuntimeError, ~r/invalid UnicodeData records/, fn ->
        Source.fetch!([unicode_data_source(url)], directory)
      end

      Task.await(server)
      refute File.exists?(directory)
    end
  end

  defp serve_once(body, status \\ "200 OK") do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_address, port}} = :inet.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)

        response = [
          "HTTP/1.1 #{status}\r\ncontent-length: ",
          Integer.to_string(byte_size(body)),
          "\r\nconnection: close\r\n\r\n",
          body
        ]

        :ok = :gen_tcp.send(socket, response)
        :ok = :gen_tcp.close(socket)
        :ok = :gen_tcp.close(listener)
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(server.pid), do: Process.exit(server.pid, :kill)
    end)

    {"http://127.0.0.1:#{port}/18.0.0/ucd/UnicodeData.txt", server}
  end
end
