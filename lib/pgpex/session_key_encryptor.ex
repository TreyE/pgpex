defmodule Pgpex.SessionKeyEncryptor do
  def encrypt_session_key({:rsa, _}, key, data) when is_binary(data) do
    encrypt_rsa_session_key(key, data)
  end

  def encrypt_session_key(kt, key, data) when is_binary(data) do
    {:error, {:unsupported_public_key_type, kt, key}}
  end

  defp encrypt_rsa_session_key(rsa_private_key, data) when is_binary(data) do
    try do
      {:ok, :public_key.encrypt_public(data, rsa_private_key, [{:rsa_padding, :rsa_pkcs1_padding}])}
    rescue
      e -> {:error, {:session_key_encryption_error, e}}
    end
  end
end
