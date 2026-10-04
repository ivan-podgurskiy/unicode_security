# Run with: mix run bench/milestone_4.exs
# Host-specific medians are descriptive, not CI timing thresholds.
warmups = 5
samples = 20

unicode_name = "bücher.例え.a"
ascii_name = "xn--bcher-kva.xn--r8jz45g.a"
internationalized_255 = Enum.join(List.duplicate(String.duplicate("é", 63), 4), ".")

long_ascii_name =
  Enum.join(
    [
      String.duplicate("a", 63),
      String.duplicate("b", 63),
      String.duplicate("c", 63),
      String.duplicate("d", 61)
    ],
    "."
  )

check_cases = [
  {"U-label valid conversion", unicode_name, true},
  {"A-label valid conversion", ascii_name, true},
  {"case/width/separator/root", "BÜCHER。a.", true},
  {"valid RTL label", "אא.a", true},
  {"valid CONTEXTJ label", "क्‍ष.a", true},
  {"invalid numeric and RTL", "1a.א", false},
  {"malformed 4096-byte Punycode", "xn--" <> String.duplicate("a", 4092), false},
  {"ASCII label 63", String.duplicate("a", 63), true},
  {"ASCII label 64", String.duplicate("a", 64), false},
  {"ASCII name 253", long_ascii_name, true},
  {"ASCII name 254", long_ascii_name <> "e", false},
  {"internationalized 255 scalars (DNS-invalid)", internationalized_255, false}
]

batch_cases =
  for count <- [1000, 2000, 4000], kind <- [:repeated, :equivalent] do
    names =
      case kind do
        :repeated -> List.duplicate("bücher.a", count)
        :equivalent -> Enum.take(Stream.cycle(["bücher.a", "BÜCHER.a", "xn--bcher-kva.a"]), count)
      end

    {"batch #{kind} #{count}", names}
  end

IO.puts(
  "Milestone 4 / #{inspect(:os.type())} / Elixir #{System.version()} / OTP #{System.otp_release()}"
)

IO.puts("#{warmups} warmups; #{samples} samples; elapsed and reductions are per invocation")

median = fn values ->
  sorted = Enum.sort(values)
  (Enum.at(sorted, 9) + Enum.at(sorted, 10)) / 2
end

measure = fn name, metadata, function ->
  for _ <- 1..warmups, do: function.()

  measurements =
    for _ <- 1..samples do
      {:reductions, before_reductions} = Process.info(self(), :reductions)
      start = System.monotonic_time()
      output = function.()

      elapsed_us =
        System.convert_time_unit(System.monotonic_time() - start, :native, :nanosecond) / 1000

      {:reductions, after_reductions} = Process.info(self(), :reductions)

      {elapsed_us, after_reductions - before_reductions,
       byte_size(:erlang.term_to_binary(output)), :erlang.phash2(output)}
    end

  {_, _, output_bytes, checksum} = List.last(measurements)
  time_us = measurements |> Enum.map(&elem(&1, 0)) |> median.()
  reductions = measurements |> Enum.map(&elem(&1, 1)) |> median.()

  IO.puts(
    "#{name}: #{metadata}, median_us=#{Float.round(time_us, 3)}, " <>
      "median_reductions=#{reductions}, output_bytes=#{output_bytes}, checksum=#{checksum}"
  )
end

for {name, input, expected_valid?} <- check_cases do
  result = UnicodeSecurity.check(input, type: :domain)

  if result.valid_input? != expected_valid?, do: raise("benchmark case validity changed: #{name}")

  scalar_count = input |> String.to_charlist() |> length()

  ascii_bytes =
    if result.domain && result.domain.ascii, do: byte_size(result.domain.ascii), else: nil

  metadata =
    "original_bytes=#{byte_size(input)}, scalars=#{scalar_count}, " <>
      "ascii_bytes=#{inspect(ascii_bytes)}, valid_input?=#{result.valid_input?}"

  measure.(name, metadata, fn -> UnicodeSecurity.check(input, type: :domain) end)
end

for {name, names} <- batch_cases do
  batch = UnicodeSecurity.check_many(names, type: :domain)
  valid_count = Enum.count(batch.results, & &1.result.valid_input?)

  if valid_count != length(names), do: raise("benchmark batch validity changed: #{name}")

  input_bytes = Enum.reduce(names, 0, fn item, total -> total + byte_size(item) end)

  scalar_count =
    Enum.reduce(names, 0, fn item, total -> total + length(String.to_charlist(item)) end)

  metadata =
    "items=#{length(names)}, original_bytes=#{input_bytes}, scalars=#{scalar_count}, " <>
      "ascii_bytes=n/a, valid_items=#{valid_count}/#{length(names)}"

  measure.(name, metadata, fn -> UnicodeSecurity.check_many(names, type: :domain) end)
end

project_root = Path.expand("..", __DIR__)
beam_root = Application.app_dir(:unicode_security, "ebin")

beams =
  Path.wildcard(Path.join(project_root, "lib/**/*.ex"))
  |> Enum.map(fn path ->
    [module] =
      Regex.run(~r/^defmodule ([\w.]+) do/m, File.read!(path), capture: :all_but_first)

    Path.join(beam_root, "Elixir.#{module}.beam")
  end)

beam_bytes = Enum.reduce(beams, 0, fn path, sum -> sum + File.stat!(path).size end)
IO.puts("Source-matched runtime BEAMs: #{length(beams)} files, #{beam_bytes} bytes")
