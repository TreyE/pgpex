defmodule Pgpex.Packets.PublicKeyEncryptedSessionKey do
  def parse(f, {:public_key_encrypted_session_key, packet_len, packet_indexes, data_len, {d_start, d_end}} = d) do
    with {:ok, _} <- :file.position(f, d_start),
         <<version::big-unsigned-integer-size(8)>> <- IO.binread(f, 1),
         <<key_id::binary-size(8)>> <- IO.binread(f, 8),
         <<pk_algo::big-unsigned-integer-size(8)>> <- IO.binread(f, 1),
         <<packet_data::binary>> <- IO.binread(f, data_len - 10) do
      {:public_key_encrypted_session_key, version, key_id, pk_algo, packet_data}
    end
  end
end
