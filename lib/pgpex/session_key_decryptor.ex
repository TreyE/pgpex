defmodule Pgpex.SessionKeyDecryptor do
  def decrypt_session_key({:rsa, _}, key, data) when is_binary(data) do
    decrypt_rsa_session_key(key, data)
  end

  defp decrypt_rsa_session_key(rsa_private_key, data) when is_binary(data) do
    try do
      {:ok, :public_key.decrypt_private(data, rsa_private_key, [{:rsa_padding, :rsa_pkcs1_padding}])}
    rescue
      e -> {:error, {:session_key_decryption_error, e}}
    end
  end
end
