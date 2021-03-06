defmodule Pgpex.SessionDecryptors.Aes do

  use Bitwise

  alias Pgpex.Primitives.MdcCalcState
  alias Pgpex.Primitives.SkipFileReader

  import Pgpex.Primitives.IOUtils

  def create_session_reader(f, key, length, positions) do
    sfr = SkipFileReader.new(f, length, positions)
    Pgpex.SessionDecryptors.AesSessionStream.new(
      Pgpex.Primitives.Behaviours.ReadableFile.wrap_as_file(SkipFileReader, sfr),
      key,
      length
    )
  end

  def verify_mdc(f, key, len, [{ds, fde}|others]) do
    with({:ok, iv} <- read_initial_iv(f, ds)) do
      sfr = SkipFileReader.new(f, len - 16, [{ds + 16, fde}|others])
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

  defp read_next_hash_part(%MdcCalcState{} = mcs) do
    case SkipFileReader.binread(mcs.skip_file_reader, 16) do
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
      {:ok, _, <<data::binary>>} ->
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
    with (:ok <- seek_or_error(f, start_pos, :iv_seek_error)) do
      binread_match(f, 16, :eof_reading_iv, :iv_too_short) do
        <<read_iv::binary-size(16)>> -> {:ok, read_iv}
      end
    end
  end

  defp read_first_block_for_verification(f) do
    binread_match(f, 16, :eof_reading_first_block, :first_block_too_short) do
      <<read_first_block::binary-size(16)>> -> {:ok, read_first_block}
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
