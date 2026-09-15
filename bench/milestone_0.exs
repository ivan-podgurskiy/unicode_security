# Run with: mix run bench/milestone_0.exs
# Deterministic inputs and sample count; timings depend on the host and VM.
iterations = 1_000
warmups = 100

cases = [
  {"ASCII identity", "paypal"},
  {"64-byte ASCII username", String.duplicate("a", 64)},
  {"Latin/Cyrillic paypal", "p\u0430yp\u0430l"},
  {"Revision 34 LTR example", "\u0391\u05E9\u05BA>1"},
  {"4096-byte bidi input", String.duplicate("אב", 1_024)},
  {"4096-byte input", String.duplicate("a", 4_096)}
]

IO.puts("Elixir #{System.version()} / OTP #{System.otp_release()}")
IO.puts("#{warmups} warmups; #{iterations} samples per case; medians in microseconds")

for {name, input} <- cases do
  for _ <- 1..warmups, do: UnicodeSecurity.skeleton(input)

  samples =
    for _ <- 1..iterations do
      started = System.monotonic_time()
      UnicodeSecurity.skeleton(input)
      elapsed = System.monotonic_time() - started
      System.convert_time_unit(elapsed, :native, :nanosecond) / 1_000
    end
    |> Enum.sort()

  median = (Enum.at(samples, div(iterations, 2) - 1) + Enum.at(samples, div(iterations, 2))) / 2
  IO.puts("#{name} (#{byte_size(input)} bytes): #{Float.round(median, 3)} us")
end

project_root = Path.expand("..", __DIR__)
source_paths = Path.wildcard(Path.join(project_root, "lib/unicode_security/data/*.ex"))
beam_root = Application.app_dir(:unicode_security, "ebin")
generated_beams = Path.wildcard(Path.join(beam_root, "Elixir.UnicodeSecurity.Data.*.beam"))

runtime_beams =
  [
    "UnicodeSecurity",
    "UnicodeSecurity.Bidi",
    "UnicodeSecurity.Bidi.Explicit",
    "UnicodeSecurity.Bidi.Weak",
    "UnicodeSecurity.Bidi.Brackets",
    "UnicodeSecurity.Confusables",
    "UnicodeSecurity.InvalidInputError",
    "UnicodeSecurity.Normalization",
    "UnicodeSecurity.Utf8"
  ]
  |> Enum.map(&Path.join(beam_root, "Elixir.#{&1}.beam"))
  |> Kernel.++(generated_beams)

for {label, paths} <- [
      {"Generated .ex", source_paths},
      {"Generated BEAM", generated_beams},
      {"All runtime BEAM", runtime_beams}
    ] do
  bytes = Enum.reduce(paths, 0, fn path, sum -> sum + File.stat!(path).size end)
  IO.puts("#{label}: #{bytes} bytes (#{length(paths)} files)")
end
