defmodule Pgpex.SessionDecryptors.AesSessionStream do

  @block_size 16
  @begin_offset 18 # For IVish CBC stuff + 2 check bytes
  @end_offset 22  # For SHA1 MDC

  @behaviour Pgpex.Primitives.Behaviours.ReadableFile

  defstruct [
    io: nil,
    start_data_position: 0,
    end_data_position: 0,
    key: nil,
    position: 0
  ]

  def new(f, key, len) do
    start_data_pos = @begin_offset
    end_data_pos = len - @end_offset - @begin_offset - 1
    %__MODULE__{
      io: f,
      key: key,
      start_data_position: start_data_pos,
      end_data_position: end_data_pos
    }
  end

  def position(%__MODULE__{position: pos} = sfr, :cur) do
    {:ok, sfr, pos}
  end

  def position(%__MODULE__{} = sfr, :bof) do
    {:ok, %__MODULE__{sfr | position: 0}, 0}
  end

  def position(%__MODULE__{end_data_position: l} = sfr, :eof) do
    {:ok, %__MODULE__{sfr | position: l + 1}, l + 1}
  end

  def position(%__MODULE__{end_data_position: l}, pos) when pos > l and pos >= 0 do
    {:error, :einval}
  end

  def position(%__MODULE__{} = sfr, pos) when pos >= 0 do
    {:ok, %__MODULE__{sfr | position: pos}, pos}
  end

  def close(%__MODULE__{io: f}) do
    :file.close(f)
  end

  def binread(%__MODULE__{end_data_position: ed_pos, position: pos},_) when pos > ed_pos do
    :eof
  end

  def binread(%__MODULE__{io: f, key: key, position: pos, end_data_position: edp} = rec,read_len) when read_len > 0 do
    read_positions(rec, f, key, pos, edp, read_len)
  end

  defp map_positions_for_read_byte(idx) do
    f_read_index = idx + @begin_offset
    {b_num, b_index} = block_indexes_for(idx)
    {f_read_index, b_num, b_index}
  end

  defp block_indexes_for(pos) do
    block_num = div(pos + @begin_offset, @block_size)
    byte_num = rem(pos + @begin_offset, @block_size)
    {block_num, byte_num}
  end

  defp position_for_block(block_index) do
    block_index * @block_size
  end

  defp read_positions(rec, f, key, current_idx, last_index, read_len) do
    suggested_end = current_idx + read_len - 1
    end_idx = case suggested_end >= last_index do
      false -> suggested_end
      _ -> last_index
    end
    {_, first_block_num, first_block_index} = map_positions_for_read_byte(current_idx)
    {_, last_block_num, last_block_index} = map_positions_for_read_byte(end_idx)
    file_begin_read_offset = position_for_block(first_block_num - 1)
    # OK while @end_offset > @block_size
    file_end_read_offset = position_for_block(last_block_num + 1) - 1
    read_length = file_end_read_offset - file_begin_read_offset + 1
    new_pos = end_idx + 1
    {:ok, _} = :file.position(f, file_begin_read_offset)
    case IO.binread(f, read_length) do
      <<data::binary>> ->
        decrypted_data = process_decryptable_bytes(data, key, first_block_index, last_block_index)
        {:ok, %__MODULE__{rec | position: new_pos}, decrypted_data}
      :eof -> :eof
      a -> {:error, a}
    end
  end

  defp process_decryptable_bytes(data, key, first_block_index, last_block_index) do
    decoded_data = run_decode(key, data, <<>>)
    :binary.part(decoded_data, first_block_index, byte_size(decoded_data) - first_block_index - (@block_size - last_block_index - 1))
  end

  defp run_decode(_, <<>>, data_so_far) do
    data_so_far
  end

  defp run_decode(_, <<_::binary-size(16)>>, data_so_far) do
    data_so_far
  end

  defp run_decode(key, <<iv::binary-size(16), data::binary-size(16), rest::binary>>, data_so_far) do
    decoded = Pgpex.SessionDecryptors.Aes.decrypt_block(iv, key, data)
    run_decode(key, <<data::binary-size(16), rest::binary>>, data_so_far <> decoded)
  end
end
