defmodule UnicodeSecurity.Idna.Punycode do
  @moduledoc """
  Bounded RFC 3492 Punycode bodies. The caller supplies the output limit;
  this module does not add or remove the `xn--` prefix.
  """

  @base 36
  @tmin 1
  @tmax 26
  @initial_n 128
  @initial_bias 72
  @max_scalar 0x10FFFF

  @spec encode([integer()], non_neg_integer()) ::
          {:ok, binary()} | {:error, :invalid_scalar | :overflow | :output_too_long}
  def encode(scalars, maximum_bytes)
      when is_list(scalars) and is_integer(maximum_bytes) and maximum_bytes >= 0 do
    if Enum.all?(scalars, &scalar?/1) do
      basics = Enum.filter(scalars, &(&1 < 128))
      basic_count = length(basics)
      total = length(scalars)
      initial_size = basic_count + if(basic_count > 0, do: 1, else: 0)

      if initial_size > maximum_bytes do
        {:error, :output_too_long}
      else
        output = if basic_count > 0, do: [?- | Enum.reverse(basics)], else: []

        encode_loop(
          scalars,
          total,
          basic_count,
          basic_count,
          @initial_n,
          0,
          @initial_bias,
          output,
          initial_size,
          maximum_bytes
        )
      end
    else
      {:error, :invalid_scalar}
    end
  end

  @spec decode(binary(), non_neg_integer()) ::
          {:ok, [integer()]}
          | {:error, :invalid_encoding | :invalid_scalar | :overflow | :output_too_long}
  def decode(body, maximum_scalars)
      when is_binary(body) and is_integer(maximum_scalars) and maximum_scalars >= 0 do
    case :binary.matches(body, "-") do
      [] ->
        decode_loop(body, [], 0, @initial_n, 0, @initial_bias, maximum_scalars)

      matches ->
        {delimiter, 1} = List.last(matches)

        if delimiter == 0 do
          {:error, :invalid_encoding}
        else
          prefix = binary_part(body, 0, delimiter)
          encoded = binary_part(body, delimiter + 1, byte_size(body) - delimiter - 1)

          cond do
            not ascii?(prefix) ->
              {:error, :invalid_encoding}

            delimiter > maximum_scalars ->
              {:error, :output_too_long}

            true ->
              decode_loop(
                encoded,
                :binary.bin_to_list(prefix),
                delimiter,
                @initial_n,
                0,
                @initial_bias,
                maximum_scalars
              )
          end
        end
    end
  end

  defp encode_loop(
         _scalars,
         total,
         total,
         _basic_count,
         _n,
         _delta,
         _bias,
         output,
         _size,
         _limit
       ),
       do: {:ok, output |> Enum.reverse() |> :erlang.list_to_binary()}

  defp encode_loop(scalars, total, h, basic_count, n, delta, bias, output, size, limit) do
    m =
      Enum.reduce(scalars, @max_scalar, fn cp, acc ->
        if cp >= n and cp < acc, do: cp, else: acc
      end)

    bound = (@max_scalar - n) * (total + 1) + total
    distance = m - n

    if distance > div(bound - delta, h + 1) do
      {:error, :overflow}
    else
      delta = delta + distance * (h + 1)

      with {:ok, delta, h, bias, output, size} <-
             encode_matching(scalars, m, delta, h, basic_count, bias, output, size, limit, bound) do
        encode_loop(scalars, total, h, basic_count, m + 1, delta + 1, bias, output, size, limit)
      end
    end
  end

  defp encode_matching([], _n, delta, h, _basic_count, bias, output, size, _limit, _bound),
    do: {:ok, delta, h, bias, output, size}

  defp encode_matching([cp | rest], n, delta, h, basic_count, bias, output, size, limit, bound) do
    cond do
      cp < n and delta >= bound ->
        {:error, :overflow}

      cp < n ->
        encode_matching(rest, n, delta + 1, h, basic_count, bias, output, size, limit, bound)

      cp == n ->
        case emit(delta, bias, output, size, limit, @base) do
          {:ok, output, size} ->
            next_bias = adapt(delta, h + 1, h == basic_count)
            encode_matching(rest, n, 0, h + 1, basic_count, next_bias, output, size, limit, bound)

          error ->
            error
        end

      true ->
        encode_matching(rest, n, delta, h, basic_count, bias, output, size, limit, bound)
    end
  end

  defp emit(q, bias, output, size, limit, k) do
    t = threshold(k, bias)

    if q < t do
      push_digit(q, output, size, limit)
    else
      digit = t + rem(q - t, @base - t)

      with {:ok, output, size} <- push_digit(digit, output, size, limit) do
        emit(div(q - t, @base - t), bias, output, size, limit, k + @base)
      end
    end
  end

  defp push_digit(_digit, _output, size, limit) when size >= limit,
    do: {:error, :output_too_long}

  defp push_digit(digit, output, size, _limit),
    do: {:ok, [digit_byte(digit) | output], size + 1}

  defp decode_loop(<<>>, output, _h, _n, _i, _bias, _limit), do: {:ok, output}

  defp decode_loop(_encoded, _output, h, _n, _i, _bias, limit) when h >= limit,
    do: {:error, :output_too_long}

  defp decode_loop(encoded, output, h, n, i, bias, limit) do
    remaining = (@max_scalar - n) * (h + 1) + h - i

    with {:ok, increment, rest} <- read_integer(encoded, bias, remaining, 0, 1, @base),
         new_i = i + increment,
         new_n = n + div(new_i, h + 1),
         :ok <- check_decoded_scalar(new_n) do
      index = rem(new_i, h + 1)

      decode_loop(
        rest,
        List.insert_at(output, index, new_n),
        h + 1,
        new_n,
        index + 1,
        adapt(increment, h + 1, i == 0),
        limit
      )
    end
  end

  defp read_integer(<<>>, _bias, _remaining, _value, _weight, _k),
    do: {:error, :invalid_encoding}

  defp read_integer(<<byte, rest::binary>>, bias, remaining, value, weight, k) do
    case byte_digit(byte) do
      :error ->
        {:error, :invalid_encoding}

      digit ->
        t = threshold(k, bias)

        cond do
          weight > remaining and digit > 0 ->
            {:error, :overflow}

          weight <= remaining and digit > div(remaining, weight) ->
            {:error, :overflow}

          digit == 0 ->
            {:ok, value, rest}

          digit < t ->
            {:ok, value + digit * weight, rest}

          true ->
            term = digit * weight
            next_remaining = remaining - term
            multiplier = @base - t

            next_weight =
              if weight > div(next_remaining, multiplier),
                do: next_remaining + 1,
                else: weight * multiplier

            read_integer(rest, bias, next_remaining, value + term, next_weight, k + @base)
        end
    end
  end

  defp check_decoded_scalar(cp) when cp > @max_scalar, do: {:error, :overflow}

  defp check_decoded_scalar(cp) when cp >= 0xD800 and cp <= 0xDFFF,
    do: {:error, :invalid_scalar}

  defp check_decoded_scalar(_cp), do: :ok

  defp adapt(delta, points, first?) do
    delta = if first?, do: div(delta, 700), else: div(delta, 2)
    adapt_loop(delta + div(delta, points), 0)
  end

  defp adapt_loop(delta, k) when delta > div((@base - 1) * @tmax, 2),
    do: adapt_loop(div(delta, @base - 1), k + @base)

  defp adapt_loop(delta, k), do: k + div(@base * delta, delta + 38)

  defp threshold(k, bias), do: min(@tmax, max(@tmin, k - bias))

  defp digit_byte(digit) when digit < 26, do: digit + ?a
  defp digit_byte(digit), do: digit - 26 + ?0

  defp byte_digit(byte) when byte in ?a..?z, do: byte - ?a
  defp byte_digit(byte) when byte in ?A..?Z, do: byte - ?A
  defp byte_digit(byte) when byte in ?0..?9, do: byte - ?0 + 26
  defp byte_digit(_byte), do: :error

  defp ascii?(binary), do: binary |> :binary.bin_to_list() |> Enum.all?(&(&1 < 128))

  defp scalar?(cp),
    do: is_integer(cp) and cp >= 0 and cp <= @max_scalar and cp not in 0xD800..0xDFFF
end
