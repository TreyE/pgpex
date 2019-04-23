defmodule Pgpex.PacketWriters.WriterUtils do
  require Bitwise

  def write_new_format_length_and_tag(tag, length) do
    first_byte = Bitwise.bor(192, tag)
    <<first_byte::big-unsigned-integer-size(8)>> <> encode_new_format_len(length)
  end

  def encode_tagged_eof(tag) do
    <<1::big-unsigned-integer-size(1),
      0::big-unsigned-integer-size(1),
      tag::big-unsigned-integer-size(4),
      3::big-unsigned-integer-size(2)>>
  end

  def new_format_tag(tag) do
    first_byte = Bitwise.bor(192, tag)
    <<first_byte::big-unsigned-integer-size(8)>>
  end

  def encode_new_format_varlen(num) do
    b_val = 224 + b_shift_to_zero(num, 0)
    <<b_val::big-unsigned-integer-size(8)>>
  end

  def encode_new_format_len(l) when l < 192 do
    <<l::big-unsigned-integer-size(8)>>
  end

  def encode_new_format_len(l) when (l > 191) and (l < 8384) do
    s_length = l - 192
    first_octet = div(s_length, 256) + 192
    second_octet = Bitwise.band(s_length, 255)
    <<first_octet::big-unsigned-integer-size(8), second_octet::big-unsigned-integer-size(8)>>
  end

  def encode_new_format_len(l) when (l > 8383) and (l < 4294967296) do
    <<255::big-unsigned-integer-size(8), l::big-unsigned-integer-size(32)>>
  end

  defp b_shift_to_zero(val, tot) when val > 1 do
    b_shift_to_zero(div(val,2), tot + 1)
  end

  defp b_shift_to_zero(_, tot) do
    tot
  end
end
