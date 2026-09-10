defmodule UnicodeSecurity.SourceTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.UnicodeData.Source

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

  defp serve_once(body) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_address, port}} = :inet.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)

        response = [
          "HTTP/1.1 200 OK\r\ncontent-length: ",
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
