# Run with: mix run bench/milestone_3.exs
# Medians describe this host and are not CI thresholds.
warmups = 5
samples = 20
ascii = String.duplicate("m", 64)
complex = "A1<ש\u05C2" <> "Αש\u05BA>1" <> "á\u0327𝐀"

cases =
  [
    {"same_skeleton? 64-byte ASCII", byte_size(ascii) * 2,
     fn -> UnicodeSecurity.same_skeleton?(ascii, ascii) end},
    {"compare 64-byte ASCII", byte_size(ascii) * 2,
     fn -> UnicodeSecurity.compare(ascii, ascii) end},
    {"same_skeleton? bidi/combining/supplementary", byte_size(complex) * 2,
     fn -> UnicodeSecurity.same_skeleton?(complex, complex) end},
    {"compare bidi/combining/supplementary", byte_size(complex) * 2,
     fn -> UnicodeSecurity.compare(complex, complex) end},
    {"conflicts? no match / 1000 streamed", 1000,
     fn ->
       UnicodeSecurity.conflicts?("m", Stream.repeatedly(fn -> "x" end) |> Stream.take(1000),
         type: :username
       )
     end},
    {"conflicts? first match / 1000 streamed", 1000,
     fn ->
       UnicodeSecurity.conflicts?(
         "m",
         Stream.concat(["rn"], Stream.repeatedly(fn -> "x" end) |> Stream.take(999)),
         type: :username
       )
     end}
  ] ++
    for n <- [1000, 2000, 4000] do
      input = List.duplicate("m", n - 1) ++ ["rn"]

      {"check_many repeated m plus rn / #{n}", n,
       fn -> UnicodeSecurity.check_many(input, type: :username) end}
    end ++
    [
      {"audit finite prefix of unbounded stream / 1000", 1000,
       fn ->
         UnicodeSecurity.audit(Stream.cycle(["m", "rn"]), type: :username) |> Enum.take(1000)
       end}
    ]

IO.puts(
  "Milestone 3 / #{:os.type() |> inspect()} / Elixir #{System.version()} / OTP #{System.otp_release()}"
)

IO.puts("#{warmups} warmups; #{samples} samples; elapsed and reductions are per invocation")

for {name, input_size, function} <- cases do
  for _ <- 1..warmups, do: function.()

  measurements =
    for _ <- 1..samples do
      {:reductions, before_reductions} = Process.info(self(), :reductions)
      start = System.monotonic_time()
      output = function.()

      elapsed =
        System.convert_time_unit(System.monotonic_time() - start, :native, :nanosecond) / 1000

      {:reductions, after_reductions} = Process.info(self(), :reductions)

      {elapsed, after_reductions - before_reductions, byte_size(:erlang.term_to_binary(output)),
       :erlang.phash2(output)}
    end

  times = Enum.map(measurements, &elem(&1, 0)) |> Enum.sort()
  reductions = Enum.map(measurements, &elem(&1, 1)) |> Enum.sort()
  median = fn sorted -> (Enum.at(sorted, 9) + Enum.at(sorted, 10)) / 2 end
  {_time, _reds, output_bytes, checksum} = List.last(measurements)
  :erlang.garbage_collect()
  {:memory, memory} = Process.info(self(), :memory)

  IO.puts(
    "#{name}: input=#{input_size}, median_us=#{Float.round(median.(times), 3)}, median_reductions=#{median.(reductions)}, output_bytes=#{output_bytes}, checksum=#{checksum}, process_bytes_after_gc=#{memory}"
  )
end

project_root = Path.expand("..", __DIR__)
beam_root = Application.app_dir(:unicode_security, "ebin")

beams =
  Path.wildcard(Path.join(project_root, "lib/**/*.ex"))
  |> Enum.map(fn path ->
    [module] =
      Regex.run(~r/defmodule ([\w.]+) do/, File.read!(path), capture: :all_but_first)

    Path.join(beam_root, "Elixir.#{module}.beam")
  end)

beam_bytes = Enum.reduce(beams, 0, fn path, sum -> sum + File.stat!(path).size end)
IO.puts("Source-matched runtime BEAMs: #{length(beams)} files, #{beam_bytes} bytes")
