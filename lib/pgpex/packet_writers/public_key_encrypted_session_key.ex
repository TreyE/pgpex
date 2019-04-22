defmodule Pgpex.PacketWriters.PublicKeyEncryptedSessionKey do

  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  def construct_packet(pk_algo_identifier, p_key, sym_algo_id, key_bytes, key_id) do
    with ({:ok, esk} <- encrypt_session_key(pk_algo_identifier, p_key, sym_algo_id, key_bytes)) do
      packet_data = <<3::big-unsigned-integer-size(8)>> <> key_id <> <<2::big-unsigned-integer-size(8)>> <> esk
      tag_and_len = Pgpex.PacketWriters.WriterUtils.write_new_format_length_and_tag(1, byte_size(packet_data))
      {:ok, tag_and_len <> packet_data}
    end
  end
  def encrypt_session_key(pk_algo_identifier, p_key, sym_algo_id, key_bytes) when is_binary(key_bytes) do
    with {:ok, sk_encoded} <- Pgpex.Primitives.SessionKey.encode_session_key(sym_algo_id, key_bytes),
         {:ok, encrypted_key} <- Pgpex.SessionKeyEncryptor.encrypt_session_key(pk_algo_identifier,p_key,sk_encoded) do
      {:ok, Pgpex.Primitives.Mpi.encode_mpi(encrypted_key)}
    end
  end

end
