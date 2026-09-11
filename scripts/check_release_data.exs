Code.require_file("check_generated.exs", __DIR__)

sources = UnicodeSecurity.UnicodeData.Source.sources()

unless Enum.all?(sources, &(&1.status == :final)) do
  IO.puts(:stderr, "release blocked: Unicode 18.0.0 data status is draft")
  System.halt(1)
end
