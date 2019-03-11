defmodule Pgpex.PacketReader do
  require Bitwise

  @packet_types %{
    0 => :reserved,
    1 => :public_key_encrypted_session_key,
    2 => :signature,
    3 => :symmetric_key_encrypted_session,
    4 => :one_pass_signature,
    5 => :secret_key,
    6 => :public_key,
    7 => :secret_subkey,
    8 => :compressed_data,
    9 => :symmetrically_encrypted_data,
    10 => :market,
    11 => :literal_data,
    12 => :trust,
    13 => :user_id,
    14 => :public_subkey,
    17 => :user_attribute,
    18 => :symmetrically_encrypted_and_integrity_protected_data,
    19 => :modification_detection_code,
    60 => :private_or_experimental,
    61 => :private_or_experimental,
    62 => :private_or_experimental,
    63 => :private_or_experimental
  }

  def read_headers(f) do
    read_headers(f,[])
  end

  defp read_headers(f, headers) do
    case read_packet_header(f) do
      :eof -> {:ok, Enum.reverse(headers)}
      {:error, e} -> {:error, e}
      a -> read_headers(f, [a|headers])
    end
  end

  def parse_packet(f, {:symmetrically_encrypted_and_integrity_protected_data, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.SymmetricallyEncryptedAndIntegrityProtectedData.parse(f, d)
  end

  def parse_packet(f, {:public_key_encrypted_session_key, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.PublicKeyEncryptedSessionKey.parse(f, d)
  end

  def parse_packet(f, {:public_key, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.PublicKey.parse(f, d)
  end

  def parse_packet(f, {:public_subkey, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.PublicKey.parse(f, d)
  end

  def parse_packet(f, {:secret_key, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.SecretKey.parse(f, d)
  end

  def parse_packet(f, {:secret_subkey, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.SecretKey.parse(f, d)
  end

  def parse_packet(_, header) do
    header
  end

  def read_packet_header(f) do
    with {:ok, start_loc} <- :file.position(f, :cur),
         {tag, len} <- read_tag_and_length(f) do
      get_body_indexes_and_skip_to_next(f, start_loc, {set_tag_type(tag), len})
    end
  end

  def read_tag_and_length(f) do
    with (<<header::binary>> <- IO.binread(f, 1)) do
      case parse_packet_header(header) do
        {:old_format, tag_bits, n} -> get_old_format_length(f, tag_bits, n)
        {:new_format, tag_bits} -> get_new_format_length(f, tag_bits)
      end
    end
  end

  def get_body_indexes_and_skip_to_next(f, start_loc, {tag, {:partial, len_so_far}}) do
    with ({:ok, data_start_pos} <- :file.position(f, :cur)) do
       {:ok, end_loc} = :file.position(f, data_start_pos + len_so_far)
       {total_len, p_indexes} = extract_part_indexes(f, len_so_far, [{data_start_pos, end_loc - 1}])
       {:ok, last_loc} = :file.position(f, :cur)
       {tag, (last_loc - start_loc), {start_loc, last_loc - 1}, total_len, p_indexes}
    end
  end

  def get_body_indexes_and_skip_to_next(f, start_loc, {tag, :eof}) do
    with ({:ok, data_start_pos} <- :file.position(f, :cur)) do
       {:ok, end_pos} = :file.position(f, :eof)
       {tag, end_pos - start_loc, {start_loc, end_pos}, end_pos - data_start_pos + 1, {data_start_pos, end_pos}}
    end
  end

  def get_body_indexes_and_skip_to_next(f, start_loc, {tag, len}) do
    with ({:ok, data_start_pos} <- :file.position(f, :cur)) do
       {:ok, end_pos} = :file.position(f, data_start_pos + len)
       {tag, end_pos - start_loc, {start_loc, data_start_pos + len - 1}, len, {data_start_pos, data_start_pos + len - 1}}
    end
  end

  defp extract_part_indexes(f, len_so_far, p_indexes) do
    with ({:ok, s_pos} <- :file.position(f, :cur)) do
      case get_new_format_length(f, "fake_tag") do
        {"fake_tag", {:partial, new_read_len}} ->
          {:ok, the_pos} = :file.position(f, :cur)
          {:ok, end_pos} = :file.position(f, the_pos + new_read_len)
          extract_part_indexes(f, len_so_far + (end_pos - s_pos), [{the_pos, end_pos - 1}|p_indexes])
        {"fake_tag", n} ->
          {:ok, the_pos} = :file.position(f, :cur)
          {:ok, end_pos} = :file.position(f, the_pos + n)
          {len_so_far + (end_pos - s_pos), Enum.reverse([{the_pos,end_pos - 1}|p_indexes])}
      end
    end
  end

  defp set_tag_type(tag_val) do
    Map.get(@packet_types, tag_val, {:invalid, tag_val})
  end

  defp get_old_format_length(f, tag, :unknown) do
    {tag, :eof}
  end

  defp get_old_format_length(f, tag, byte_count) do
    bit_size = byte_count * 8
    with(<<num::big-unsigned-integer-size(bit_size)>> <- IO.binread(f, byte_count)) do
      {tag, num}
    end
  end

  defp get_new_format_length(f, tag) do
    with (<<len_byte::binary>> <- IO.binread(f, 1)) do
      case new_length_format_first_byte(len_byte) do
        {:done, len} -> {tag, len}
        {:one_more, first_byte_val} -> read_additional_new_length_byte(f, tag, first_byte_val)
        :four_more -> read_four_new_length_bytes(f, tag)
        a -> {tag, a}
      end
    end
  end

  defp read_additional_new_length_byte(f, tag, first_byte_val) do
    with(<<byte_val::big-unsigned-integer-size(8)>> <- IO.binread(f,1)) do
      {tag, first_byte_val + byte_val}
    end
  end

  defp read_four_new_length_bytes(f, tag) do
    with(<<bytes_value::big-unsigned-integer-size(32)>> <- IO.binread(f,4)) do
      {tag, bytes_value}
    end
  end

  # Old packet format
  def parse_packet_header(<<1::unsigned-integer-size(1),0::big-unsigned-integer-size(1), tag_bits::big-unsigned-integer-size(4), 0::big-unsigned-integer-size(2)>>) do
    {:old_format, tag_bits, 1}
  end

  def parse_packet_header(<<1::unsigned-integer-size(1),0::big-unsigned-integer-size(1), tag_bits::big-unsigned-integer-size(4), 1::big-unsigned-integer-size(2)>>) do
    {:old_format, tag_bits, 2}
  end

  def parse_packet_header(<<1::unsigned-integer-size(1),0::big-unsigned-integer-size(1), tag_bits::big-unsigned-integer-size(4), 2::big-unsigned-integer-size(2)>>) do
    {:old_format, tag_bits, 4}
  end

  def parse_packet_header(<<1::unsigned-integer-size(1),0::big-unsigned-integer-size(1), tag_bits::big-unsigned-integer-size(4), 3::big-unsigned-integer-size(2)>>) do
    {:old_format, tag_bits, :unknown}
  end

  # New Packet format
  def parse_packet_header(<<1::unsigned-integer-size(1),1::big-unsigned-integer-size(1), tag_bits::big-unsigned-integer-size(6)>>) do
    {:new_format, tag_bits}
  end

  defp new_length_format_first_byte(<<255::big-unsigned-integer-size(8)>>) do
    :four_more
  end

  defp new_length_format_first_byte(<<nlf::big-unsigned-integer-size(8)>>) when nlf < 192 do
    {:done, nlf}
  end

  defp new_length_format_first_byte(<<nlf::big-unsigned-integer-size(8)>>) when nlf > 191 and nlf < 224 do
    {:one_more, ((nlf - 192) * 256) + 192}
  end

  defp new_length_format_first_byte(<<size::big-unsigned-integer-size(8)>>) when size > 223 and size < 255 do
    banded = Bitwise.band(size, 0x1F)
    first_chunk_size = trunc(:math.pow(2, banded))
    {:partial, first_chunk_size}
  end
end
