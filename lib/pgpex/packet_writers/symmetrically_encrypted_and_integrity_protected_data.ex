defmodule Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedData do
  defstruct [
    io: nil,
    session_key: nil,
    encrypt_params: nil,
    hash_status: nil,
    buffer: <<>>,
    current_iv: <<>>,
    encryptor: nil,
    finalizer: nil,
    data_prefix_written: false
  ]

  def initialize({:aes, key}, f, data_len) do
    write_packet_header(f, data_len, 16)
    {first_block, data_prefix, h_update, encryptor, finalizer} = Pgpex.SessionEncryptors.Aes.init_for(key)
    IO.binwrite(f, first_block)
    %__MODULE__{
      io: f,
      hash_status: h_update,
      current_iv: first_block,
      buffer: data_prefix,
      encryptor: encryptor,
      finalizer: finalizer,
      session_key: key
    }
  end

  def write(%__MODULE__{} = w, new_data) do
    updated_hash = :crypto.hash_update(w.hash_status, new_data)
    {new_iv, new_buff, to_write} = w.encryptor.(w.buffer, new_data, w.current_iv, w.session_key)
    IO.binwrite(w.io, to_write)
    %__MODULE__{
      w |
        current_iv: new_iv,
        buffer: new_buff,
        hash_status: updated_hash
    }
  end

  def finalize(%__MODULE__{} = w_before_mdc_bytes) do
    w = write(
      w_before_mdc_bytes,
      <<0xD3::big-unsigned-integer-size(8), 0x14::big-unsigned-integer-size(8)>>
    )
    last_bytes = w.finalizer.(w.buffer, w.hash_status, w.current_iv, w.session_key)
    IO.binwrite(w.io, last_bytes)
  end

  def write_packet_header(f, data_len, b_size) do
    all_data_size = data_len + 23 + b_size + 2
    tag_and_len = Pgpex.PacketWriters.WriterUtils.write_new_format_length_and_tag(
      18,
      all_data_size
    )
    IO.binwrite(f, tag_and_len <> <<1::big-integer-unsigned-size(8)>>)
  end
end
