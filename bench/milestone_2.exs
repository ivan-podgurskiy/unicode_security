# Run with: mix run bench/milestone_2.exs
# Fixed original inputs; machine-dependent medians are not CI assertions.
iterations = 1_000
warmups = 100

cases = [
  {"64-byte ASCII username", String.duplicate("a", 64), :username},
  {"64-byte ASCII MA mapping", String.duplicate("m", 64), :username},
  {"64-byte varied ASCII username", String.duplicate("alice-smth_0123.", 4), :username},
  {"International username", "aねガ", :username},
  {"International tenant slug", "café-東京", :tenant_slug},
  {"International organization", "Acme & 株式会社", :organization_name},
  {"4096-byte ASCII", String.duplicate("a", 4096), :username},
  {"4096-byte combining sequence", String.duplicate("a\u0301", 1365) <> "a", :username},
  {"4096-byte bidi", String.duplicate("אב", 1024), :username},
  {"4096-byte joiners", String.duplicate("\u200D", 1365) <> "a", :username}
]

IO.puts("Elixir #{System.version()} / OTP #{System.otp_release()}")
IO.puts("#{warmups} warmups; #{iterations} samples; medians in microseconds")

for {name, input, type} <- cases do
  function = fn -> UnicodeSecurity.check(input, type: type) end
  for _ <- 1..warmups, do: function.()

  samples =
    for _ <- 1..iterations do
      started = System.monotonic_time()
      function.()
      System.convert_time_unit(System.monotonic_time() - started, :native, :nanosecond) / 1000
    end
    |> Enum.sort()

  median = (Enum.at(samples, div(iterations, 2) - 1) + Enum.at(samples, div(iterations, 2))) / 2
  IO.puts("#{name} / #{type} (#{byte_size(input)} bytes): #{Float.round(median, 3)} us")
end

project_root = Path.expand("..", __DIR__)
beam_root = Application.app_dir(:unicode_security, "ebin")

for {label, paths} <- [
      {"Generated .ex", Path.wildcard(Path.join(project_root, "lib/unicode_security/data/*.ex"))},
      {"Generated BEAM",
       Path.wildcard(Path.join(beam_root, "Elixir.UnicodeSecurity.Data.*.beam"))},
      {"All runtime BEAM",
       Path.wildcard(Path.join(project_root, "lib/**/*.ex"))
       |> Enum.map(fn path ->
         [module] =
           Regex.run(~r/defmodule ([\w.]+) do/, File.read!(path), capture: :all_but_first)

         Path.join(beam_root, "Elixir.#{module}.beam")
       end)}
    ] do
  bytes = Enum.reduce(paths, 0, fn path, sum -> sum + File.stat!(path).size end)
  IO.puts("#{label}: #{bytes} bytes (#{length(paths)} files)")
end
