defmodule Pgpex.Primatives.MdcCalcState do
  @sha_size 20

  defstruct [
    last_iv: nil,
    key: nil,
    hash_state: nil,
    skip_file_reader: nil,
    last_non_hash_data_position: 0,
    current_position: 0,
    buffer: <<>>
  ]

  def add_new_iv_and_bytes(mdc, iv, new_bytes, sfr) do
    new_pos = mdc.current_position + byte_size(new_bytes)
    {for_hash, for_buff} = add_to_buffer(mdc.buffer, new_bytes)
    new_hash_state = :crypto.hash_update(mdc.hash_state, for_hash)
    %__MODULE__{
      mdc |
        current_position: new_pos,
        buffer: for_buff,
        last_iv: iv,
        hash_state: new_hash_state,
        skip_file_reader: sfr
    }
  end

  def add_new_bytes_and_finish(mdc, new_bytes) do
    new_pos = mdc.current_position + byte_size(new_bytes)
    {for_hash, for_buff} = add_to_buffer(mdc.buffer, new_bytes)
    new_hash_state = :crypto.hash_update(mdc.hash_state, for_hash)
    finish(%__MODULE__{
      mdc |
        current_position: new_pos,
        buffer: for_buff,
        hash_state: new_hash_state
    })
  end

  def finish(%__MODULE__{buffer: buff, hash_state: hs}) do
    digest = :crypto.hash_final(hs)
    case buff do
      ^digest -> {:ok, digest}
      _ -> {:error, {:mdc_mismatch, buff, digest}}
    end
  end

  defp add_to_buffer(buff, new_bytes) do
    total_size = byte_size(buff) + byte_size(new_bytes)
    full_buff = buff <> new_bytes
    size_difference = total_size - @sha_size
    case (size_difference > 0) do
      false -> {<<>>, full_buff}
      _ ->
        {
          :binary.part(full_buff, 0, size_difference),
          :binary.part(full_buff, size_difference, @sha_size)
        }
    end
  end
end
