defmodule Pgpex.PacketWriters.PublicKeyEncryptedSessionKey do

  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  defstruct [
    version: 3,
    key_id: nil,
    key_kind: {:rsa, :both},
    encrypted_session_key: nil
  ]

  def encrypt_session_key(sym_algo_id, key_bytes) when is_binary(key_bytes) do
    with ({:ok, sk_encoded} <- Pgpex.Primitives.SessionKey.encode_session_key(sym_algo_id, key_bytes)) do

    end
  end

end
