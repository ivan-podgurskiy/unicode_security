defmodule UnicodeSecurity.PathsTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Test.Paths

  test "treats slash style and drive-letter case as the same path" do
    assert Paths.same?("C:\\Users\\Temp/pkg", "c:/Users/Temp/pkg")
    assert Paths.same?("/tmp/pkg", "/tmp/pkg")
    refute Paths.same?("C:/pkg/a", "C:/pkg/b")
    refute Paths.same?("/tmp/a", "/tmp/b")
  end
end
