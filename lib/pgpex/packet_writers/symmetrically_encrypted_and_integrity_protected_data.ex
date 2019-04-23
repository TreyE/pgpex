defmodule Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedData do
  defstruct [
    io: nil,
    session_key: nil,
    encrypt_params: nil,
    hash_status: nil,
    write_buffer: <<>>,
    buffer: <<>>,
    current_iv: <<>>,
    encryptor: nil,
    finalizer: nil,
    header_written: false
  ]

  @behaviour Pgpex.Primitives.Behaviours.WritableFile

  def wrap_as_file(%__MODULE__{} = w) do
    Pgpex.Primitives.Behaviours.WritableFile.wrap_as_file(__MODULE__, w)
  end

  def initialize({:aes, key}, f) do
    {first_block, data_prefix, h_update, encryptor, finalizer} = Pgpex.SessionEncryptors.Aes.init_for(key)
    tag = Pgpex.PacketWriters.WriterUtils.new_format_tag(18)
    IO.binwrite(f, tag)
    %__MODULE__{
      io: f,
      hash_status: h_update,
      current_iv: first_block,
      buffer: data_prefix,
      encryptor: encryptor,
      finalizer: finalizer,
      session_key: key,
      write_buffer: (<<1::big-integer-unsigned-size(8)>> <> first_block)
    }
  end

  def binwrite(%__MODULE__{} = w, new_data) do
    updated_hash = :crypto.hash_update(w.hash_status, new_data)
    {new_iv, new_buff, to_write} = w.encryptor.(w.buffer, new_data, w.current_iv, w.session_key)
    new_full_buff = w.write_buffer <> to_write
    {remaining_buff, h_written} = chomp_me(new_full_buff, w.io, w.header_written)
    {:ok, %__MODULE__{
      w |
        current_iv: new_iv,
        buffer: new_buff,
        hash_status: updated_hash,
        write_buffer: remaining_buff,
        header_written: h_written
    }}
  end

  defp chomp_me(<<eatable::binary-size(512), rest::binary>>, f, _) do
    v_len = Pgpex.PacketWriters.WriterUtils.encode_new_format_varlen(512)
    IO.binwrite(
      f,
      v_len
    )
    IO.binwrite(
      f,
      eatable
    )
    chomp_me(rest, f, true)
  end

  defp chomp_me(<<left::binary>>, _, h_written) do
    {left, h_written}
  end

  def finalize(%__MODULE__{} = w_before_mdc_bytes) do
    {:ok, w} = binwrite(
      w_before_mdc_bytes,
      <<0xD3::big-unsigned-integer-size(8), 0x14::big-unsigned-integer-size(8)>>
    )
    last_bytes = w.finalizer.(w.buffer, w.hash_status, w.current_iv, w.session_key)
    bytes_to_write = w.write_buffer <> last_bytes
    case w.header_written do
      false ->
        IO.binwrite(
          w.io,
          Pgpex.PacketWriters.WriterUtils.encode_new_format_len(byte_size(bytes_to_write))
        )
      _ -> :ok
    end
    IO.binwrite(w.io, bytes_to_write)
  end
end
