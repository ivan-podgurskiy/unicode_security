defmodule UnicodeSecurity.DomainTest do
  use ExUnit.Case, async: true

  alias UnicodeSecurity.Domain
  alias UnicodeSecurity.Domain.Reasons
  alias UnicodeSecurity.InvalidDomainError

  test "normalizes names while retaining original label and root source" do
    result = UnicodeSecurity.check("BÜCHER。a.\u00AD", type: :domain)
    assert result.input == "BÜCHER。a.\u00AD"
    assert result.policy == :strict
    assert result.valid_input?
    assert result.domain.unicode == "bücher.a."
    assert result.domain.ascii == "xn--bcher-kva.a."
    assert result.domain.trailing_dot?
    assert [first, middle, root] = result.domain.labels
    assert first.input == "BÜCHER"
    assert middle.byte_offset == byte_size("BÜCHER。")
    assert root.input == "\u00AD"
    assert root.root? and root.unicode == "" and root.ascii == ""
    assert root.skeleton == nil and root.reasons == [] and root.verdict == :safe
  end

  test "invalid label retains valid neighbor but no whole-name key" do
    result = UnicodeSecurity.check("xn--abc-.a", type: :domain)
    refute result.valid_input?
    assert result.skeleton == nil and result.scripts == nil
    assert result.domain.unicode == nil and result.domain.ascii == nil
    assert [bad, good] = result.domain.labels
    refute bad.valid_idna?
    assert good.valid_idna? and good.skeleton == "a"
  end

  test "whole-domain bidi activation is preserved through the public adapter" do
    refute UnicodeSecurity.check("1a.א", type: :domain).valid_input?
    assert UnicodeSecurity.check("1a.a", type: :domain).valid_input?
  end

  test "domain primitive validates hostname before returning a boundary key" do
    assert Domain.key(Domain.validate!("BÜCHER。a.\u00AD")) == "bücher.a"
    error = assert_raise InvalidDomainError, fn -> Domain.validate!("xn--abc-.a") end
    assert error.reason == :domain_invalid_alabel
    assert error.byte_offset == 0
    assert error.label_index == 0
    assert Exception.message(error) == "Input is not a valid domain name"
  end

  test "hostname syntax and IPv4 literals are invalid even after mapping" do
    for scalar <- [?:, ?/, ?\\, ?@, ??, ?#, ?[, ?], ?*] do
      refute UnicodeSecurity.check("a#{<<scalar::utf8>>}b", type: :domain).valid_input?
    end

    for input <- ["127.0.0.1", "１２７.０.０.１", "00127.000.0.1"] do
      result = UnicodeSecurity.check(input, type: :domain)
      refute result.valid_input?
      assert Enum.any?(result.reasons, &(&1.code == :domain_invalid_hostname))
    end

    assert UnicodeSecurity.check("123", type: :domain).valid_input?
    assert UnicodeSecurity.check("0x7f.1", type: :domain).valid_input?
  end

  test "whole-name IDNA validity includes hostname restrictions" do
    for input <- ["127.0.0.1", "１２７.０.０.１", "00127.000.0.1", "127.0.0.1."] do
      result = UnicodeSecurity.check(input, type: :domain)
      refute result.valid_input?
      refute result.domain.valid_idna?
      assert Enum.any?(result.reasons, &(&1.code == :domain_invalid_hostname))
    end

    assert UnicodeSecurity.check("123.456.789.012", type: :domain).domain.valid_idna?
    assert UnicodeSecurity.check("aа.a", type: :domain).domain.valid_idna?
  end

  test "invalid labels have no public ASCII form while valid neighbors retain theirs" do
    bidi = UnicodeSecurity.check("1a.א", type: :domain)
    assert Enum.map(bidi.domain.labels, & &1.ascii) == [nil, "xn--4db"]
    refute hd(bidi.domain.labels).valid_idna?

    for input <- ["xn--a-bcb.good", "xn--u-ccb.good"] do
      result = UnicodeSecurity.check(input, type: :domain)
      assert Enum.map(result.domain.labels, & &1.ascii) == [nil, "good"]
      refute hd(result.domain.labels).valid_idna?
    end

    empty = UnicodeSecurity.check("a..good", type: :domain)
    assert Enum.map(empty.domain.labels, & &1.ascii) == ["a", nil, "good"]

    assert Enum.map(UnicodeSecurity.check("a.", type: :domain).domain.labels, & &1.ascii) ==
             ["a", ""]
  end

  test "decoded hostname syntax uses original A-label scope after ignored source" do
    result = UnicodeSecurity.check("\u00ADxn--:-bga.good", type: :domain)

    assert Enum.any?(result.reasons, fn reason ->
             reason.code == :domain_invalid_hostname and
               reason.details.rule == :hostname_syntax and
               reason.details.codepoint == ?: and
               reason.details.source_scope == :label and
               reason.byte_offset == 0 and reason.codepoint_index == 0 and
               reason.details.label_index == 0
           end)

    assert Enum.any?(result.reasons, fn reason ->
             reason.code == :domain_invalid_hostname and
               reason.details.rule == :hostname_syntax and
               reason.details.codepoint == ?: and
               reason.details.source_scope == :scalar and
               reason.byte_offset == 6 and reason.codepoint_index == 5 and
               reason.details.label_index == 0
           end)
  end

  test "zero-length names do not claim to exceed the DNS maximum" do
    for input <- ["", ".", "\u00AD", "\u00AD."] do
      result = UnicodeSecurity.check(input, type: :domain)
      refute result.valid_input?
      assert Enum.any?(result.reasons, &(&1.code == :domain_empty_label))
      refute Enum.any?(result.reasons, &(&1.code == :domain_name_too_long))
    end
  end

  test "hostname syntax mapped from fullwidth source remains attributable" do
    result = UnicodeSecurity.check("a／b.good", type: :domain)
    refute result.valid_input?
    reason = Enum.find(result.reasons, &(&1.code == :domain_invalid_hostname))
    assert reason.byte_offset == 1
    assert reason.codepoint_index == 1
    assert reason.details.label_index == 0
    assert reason.details.label == "a／b"
    assert reason.details.rule == :hostname_syntax
    assert reason.details.codepoint == ?/
    assert reason.details.source_scope == :scalar
  end

  test "all separators preserve their original spans" do
    for separator <- [".", "。", "．", "｡"] do
      result = UnicodeSecurity.check("a" <> separator <> "b", type: :domain)
      assert result.valid_input?
      assert result.domain.ascii == "a.b"
      assert [a, b] = result.domain.labels
      assert a.byte_offset == 0 and a.byte_length == 1
      assert b.byte_offset == 1 + byte_size(separator)
      assert b.codepoint_index == 2
    end
  end

  test "empty and interior labels fail while one final root is accepted" do
    for input <- ["", ".", ".a", "a..b", "a.."] do
      result = UnicodeSecurity.check(input, type: :domain)
      refute result.valid_input?
      assert Enum.any?(result.reasons, &(&1.code == :domain_empty_label))
    end

    assert UnicodeSecurity.check("a.", type: :domain).valid_input?
    assert Domain.key(Domain.validate!("a.")) == "a"
  end

  test "ASCII label and full-name octet limits exclude optional root" do
    assert UnicodeSecurity.check(String.duplicate("a", 63) <> ".", type: :domain).valid_input?
    too_long = UnicodeSecurity.check(String.duplicate("a", 64) <> ".ok", type: :domain)
    refute too_long.valid_input?
    assert Enum.any?(too_long.reasons, &(&1.code == :domain_label_too_long))
    assert List.last(too_long.domain.labels).ascii == "ok"

    name253 =
      Enum.join(
        [
          String.duplicate("a", 63),
          String.duplicate("b", 63),
          String.duplicate("c", 63),
          String.duplicate("d", 61)
        ],
        "."
      )

    assert byte_size(name253) == 253
    assert UnicodeSecurity.check(name253 <> ".", type: :domain).valid_input?
    result254 = UnicodeSecurity.check(name253 <> "e", type: :domain)
    refute result254.valid_input?
    assert Enum.any?(result254.reasons, &(&1.code == :domain_name_too_long))
  end

  test "each label has isolated security facts and explicit preset" do
    separated = UnicodeSecurity.check("a.α", type: :domain, policy: :default)
    assert separated.valid_input?
    assert separated.policy == :default
    refute separated.mixed_script?
    assert Enum.all?(separated.domain.labels, &(not &1.mixed_script?))

    mixed = UnicodeSecurity.check("aα.b", type: :domain, policy: :permissive)
    assert mixed.valid_input?
    assert mixed.mixed_script?
    assert hd(mixed.domain.labels).mixed_script?
    refute List.last(mixed.domain.labels).mixed_script?

    separated_digits = UnicodeSecurity.check("1.९", type: :domain)
    assert separated_digits.valid_input?
    refute separated_digits.mixed_number?
    assert Enum.all?(separated_digits.domain.labels, &(not &1.mixed_number?))

    combined_digits = UnicodeSecurity.check("1९.a", type: :domain)
    assert combined_digits.valid_input?
    assert combined_digits.mixed_number?
    assert hd(combined_digits.domain.labels).mixed_number?
  end

  test "validation precedence, decoder errors, and deviation-only validity" do
    assert_raise ArgumentError, fn -> Domain.validate!(nil) end

    assert_raise UnicodeSecurity.InvalidInputError, fn ->
      Domain.validate!(<<255>>)
    end

    assert_raise UnicodeSecurity.InvalidInputError, fn ->
      Domain.validate!(:binary.copy("a", 4097))
    end

    result = UnicodeSecurity.check("faß.de", type: :domain)
    assert result.valid_input?
    assert Enum.any?(result.reasons, &(&1.code == :domain_deviation_character))
    assert Domain.key(Domain.validate!("faß.de")) != nil
  end

  test "primitive selects the first original-position validity reason" do
    input = "a..xn--abc-"
    result = UnicodeSecurity.check(input, type: :domain, policy: :permissive)
    first = Enum.find(result.reasons, &Reasons.validity?/1)

    assert {first.code, first.byte_offset, first.details.label_index} ==
             {:domain_empty_label, 2, 1}

    error = assert_raise InvalidDomainError, fn -> Domain.validate!(input) end

    assert {error.reason, error.byte_offset, error.label_index} ==
             {first.code, first.byte_offset, first.details.label_index}
  end

  test "A-label findings use original label start even after an ignored prefix" do
    input = "\u00ADxn--abc-.good"
    result = UnicodeSecurity.check(input, type: :domain)
    finding = Enum.find(result.reasons, &(&1.code == :domain_invalid_alabel))
    assert finding.byte_offset == 0
    assert finding.codepoint_index == 0
    assert finding.details.source_scope == :label
    assert finding.details.label == "\u00ADxn--abc-"
    assert Enum.at(result.domain.labels, 1).skeleton == "good"
  end

  test "valid A-label security findings retain label-scope source offset" do
    result = UnicodeSecurity.check("xn--jea", type: :domain)
    assert result.valid_input?
    assert result.domain.unicode == "ĕ"

    assert [
             %{
               code: :restricted_character,
               byte_offset: 0,
               codepoint_index: 0,
               details: %{source_scope: :label, codepoint: 0x0115}
             }
           ] = result.reasons
  end

  test "deviation codepoint names the mapped scalar at original position" do
    result = UnicodeSecurity.check("ẞ.de", type: :domain)
    assert result.valid_input?
    finding = Enum.find(result.reasons, &(&1.code == :domain_deviation_character))
    assert finding.byte_offset == 0
    assert finding.codepoint_index == 0
    assert finding.details.codepoint == ?ß

    decoded = UnicodeSecurity.check("xn--fa-hia.de", type: :domain)
    assert decoded.valid_input?
    finding = Enum.find(decoded.reasons, &(&1.code == :domain_deviation_character))
    assert finding.byte_offset == 0
    assert finding.details.codepoint == ?ß
    assert finding.details.source_scope == :label
  end

  test "mapped STD3 and decoded A-label leading mark name the offending scalar" do
    mapped = UnicodeSecurity.check("a＿b.good", type: :domain)
    refute mapped.valid_input?
    finding = Enum.find(mapped.reasons, &(&1.code == :domain_invalid_ascii))
    assert {finding.byte_offset, finding.codepoint_index} == {1, 1}
    assert finding.details.codepoint == ?_
    assert finding.details.source_scope == :scalar

    decoded = UnicodeSecurity.check("xn--a-bcb.good", type: :domain)
    refute decoded.valid_input?
    finding = Enum.find(decoded.reasons, &(&1.code == :domain_idna_disallowed))
    assert finding.byte_offset == 0
    assert finding.details.rule == :leading_mark
    assert finding.details.codepoint == 0x0308
    assert finding.details.source_scope == :label
  end

  test "independent errors sort at original scalar boundaries" do
    input = "a＿b..xn--abc-.good"
    result = UnicodeSecurity.check(input, type: :domain)
    refute result.valid_input?
    assert Enum.any?(result.reasons, &(&1.code == :domain_invalid_ascii))
    assert Enum.any?(result.reasons, &(&1.code == :domain_empty_label))
    assert Enum.any?(result.reasons, &(&1.code == :domain_invalid_alabel))
    boundaries = input |> UnicodeSecurity.Utf8.decode!() |> Enum.map(&elem(&1, 1))

    for reason <- result.reasons, not is_nil(reason.byte_offset) do
      assert reason.byte_offset in boundaries or reason.byte_offset == byte_size(input)
      assert reason.details.original_byte_offset == reason.byte_offset
    end
  end

  test "prepared domain reuses label keys and original NFD" do
    validated = Domain.validate!("BÜCHER。a.\u00AD")
    key = Domain.key(validated)
    prepared = Domain.prepare(validated, key)
    assert prepared.skeleton == key
    assert prepared.unicode_vector == ["bücher", "a"]
    assert Enum.map(prepared.labels, & &1.skeleton) == validated.label_skeletons

    assert prepared.nfd ==
             UnicodeSecurity.Normalization.nfd_scalars(String.to_charlist("BÜCHER。a.\u00AD"))

    assert prepared.scripts == [:latin]
    assert prepared.resolved == [:hntl, :latin]
    assert prepared.units == validated.units
  end

  test "domain options validate before malformed content and scripts remain scoped" do
    assert_raise ArgumentError, fn ->
      UnicodeSecurity.check(<<255>>, type: :domain, policy: :unknown)
    end

    assert_raise ArgumentError, fn ->
      UnicodeSecurity.check(<<255>>, type: :domain, allowed_scripts: [:not_a_script])
    end

    result = UnicodeSecurity.check("a.α", type: :domain, denied_scripts: [:greek])
    assert result.valid_input?
    assert Enum.any?(List.last(result.domain.labels).reasons, &(&1.code == :denied_script))
    refute Enum.any?(hd(result.domain.labels).reasons, &(&1.code == :denied_script))
  end

  test "valid dangerous IDNA name retains a usable key and per-label reasons" do
    result = UnicodeSecurity.check("раypal.com", type: :domain)
    assert result.valid_input?
    assert result.verdict == :dangerous
    assert is_binary(result.skeleton)
    assert hd(result.domain.labels).mixed_script?
    refute List.last(result.domain.labels).mixed_script?
  end

  test "NFC composition attributes security findings to the earliest source scalar" do
    result = UnicodeSecurity.check("e\u0306.com", type: :domain)
    assert result.valid_input?
    finding = Enum.find(result.reasons, &(&1.code == :restricted_character))
    assert finding.byte_offset == 0
    assert finding.codepoint_index == 0
    assert finding.details.codepoint == 0x0115
    assert finding.details.label == "e\u0306"
    assert finding.details.source_scope == :scalar
  end
end
