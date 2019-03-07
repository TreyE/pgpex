defmodule Pgpex.SessionDecryptors.Aes do

  use Bitwise

  defmodule MdcCalcState do
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

  def read_and_verify_mdc(f, key, len, [{ds, fde}|others]) do
    with({:ok, iv} <- read_initial_iv(f, ds)) do
      sfr = Pgpex.Primatives.SkipFileReader.new(f, len - 16, [{ds + 16, fde}|others])
      hs = :crypto.hash_init(:sha)
      d_iv = decrypt_block(<<0::big-unsigned-integer-size(128)>>, key, iv)
      hs_start = :crypto.hash_update(hs, d_iv)
      mdc_state = %MdcCalcState{
        last_iv: iv,
        key: key,
        hash_state: hs_start,
        skip_file_reader: sfr,
        last_non_hash_data_position: len - 21
      }
      read_next_hash_part(mdc_state)
    end
  end

  defp read_next_hash_part(
      %MdcCalcState{
        current_position: cp,
        skip_file_reader: sfr,
        last_iv: iv
      } = mcs
    ) do
    case Pgpex.Primatives.SkipFileReader.binread(sfr, 16) do
      :eof -> :ok
      {:ok, sfr, <<data::binary-size(16)>>} ->
        new_bytes = decrypt_block(mcs.last_iv, mcs.key, data)
        read_next_hash_part(
          MdcCalcState.add_new_iv_and_bytes(
          mcs,
          data,
          new_bytes,
          sfr
         )
        )
      {:ok, sfr, <<data::binary>>} ->
        new_bytes = decrypt_block(mcs.last_iv, mcs.key, data)
        MdcCalcState.add_new_bytes_and_finish(
          mcs,
          new_bytes
        )
      :eof -> MdcCalcState.finish(mcs)
      a -> {:error, {:reading_body_for_mdc_check_error, a}}
    end
  end

  def read_and_verify_first_block(f, start_pos, key) do
    with {:ok, iv} <- read_initial_iv(f, start_pos),
         {:ok, f_block} <- read_first_block_for_verification(f) do
      <<_::binary-size(14),iv_check_bytes::binary-size(2)>> = decrypt_block(<<0::big-unsigned-integer-size(128)>>, key, iv)
      <<session_check_bytes::binary-size(2),_::binary>> = decrypt_block(iv, key, f_block)
      case iv_check_bytes do
        ^session_check_bytes -> :ok
        _ -> {:error, {:session_iv_check_mismatch, iv_check_bytes, session_check_bytes}}
      end
    end
  end

  defp read_initial_iv(f, start_pos) do
    :file.position(f, start_pos)
    case IO.binread(f, 16) do
      <<read_iv::binary-size(16)>> -> {:ok, read_iv}
      <<bad_data::binary>> -> {:error, {:iv_too_short, bad_data}}
      :eof -> {:error, :eof_reading_iv}
      a -> {:error, a}
    end
  end

  defp read_first_block_for_verification(f) do
    case IO.binread(f, 16) do
      <<read_first_block::binary-size(16)>> -> {:ok, read_first_block}
      <<bad_data::binary>> -> {:error, {:first_block_to_short, bad_data}}
      :eof -> {:error, :eof_reading_first_block}
      a -> {:error, a}
    end
  end

  def decrypt_block(iv, key, cyphertext) do
    ct_size = byte_size(cyphertext)
    <<ctext_int::big-unsigned-integer-size(128)>> = cyphertext <> :binary.copy(<<0>>, 16 - ct_size)
    <<before_ct_apply_int::big-unsigned-integer-size(128)>> = :crypto.block_encrypt(:aes_ecb, key, iv)
    xored = Bitwise.bxor(before_ct_apply_int, ctext_int)
    :binary.part(<<xored::big-unsigned-integer-size(128)>>, 0, ct_size)
  end

end
