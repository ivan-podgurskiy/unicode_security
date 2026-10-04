Code.require_file("check_generated.exs", __DIR__)

sources = UnicodeSecurity.UnicodeData.Source.sources()

case UnicodeSecurity.UnicodeData.Release.non_final_source_names(sources) do
  [] ->
    :ok

  _names ->
    IO.puts(:stderr, "release blocked: Unicode 18.0.0 data status is draft")
    System.halt(1)
end
