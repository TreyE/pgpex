defmodule Pgpex.Packets.PublicKeyEncryptedSessionKey do
  @type t :: %__MODULE__{
    version: 3,
    key_id: binary(),
    key_kind: key_kind(),
    encrypted_session_key: binary()
  }
  @type key_kind :: {:rsa, :both} | {:rsa, :encrypt} | {:rsa, :sign}

  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  @type key_provider :: (key_kind(), binary() -> {:error, any()} | {:ok, term()} | {:ok, [term()]} )

  defstruct [
    version: 3,
    key_id: nil,
    key_kind: {:rsa, :both},
    encrypted_session_key: nil
  ]

  @spec parse(
          any(),
          Pgpex.PacketHeader.t(:public_key_encrypted_session_key)
        ) ::
          {:error,
             atom()
             | {:version_key_id_and_pk_algo_data_read_error,
                atom() | {:no_translation, :unicode, :latin1}}
             | {:version_key_id_and_pk_algo_data_too_short, binary()}
             | {:no_translation, :unicode, :latin1}}
          | t()
  def parse(f, %Pgpex.PacketHeader{tag: :public_key_encrypted_session_key, data_locations: {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, version, key_id, pk_algo} <- read_version_key_id_and_pk_algo(f),
         key_kind = Map.get(@pk_algo_identifiers, pk_algo, {:unknown, :unknown}),
         {:ok, encrypted_session_key} <- read_encrypted_session_key(key_kind, f) do
      %__MODULE__{
        version: version,
        key_id: key_id,
        key_kind: key_kind,
        encrypted_session_key: encrypted_session_key
      }
    end
  end

  @spec decrypt_session_key(t(), key_provider()) :: {:ok, binary()} | {:ok, [binary]} | {:error, any()}
  def decrypt_session_key(%__MODULE__{key_kind: k_kind,key_id: k_id, encrypted_session_key: esk}, key_provider) do
    case key_provider.(k_kind, k_id) do
      {:ok, keys} when is_list(keys) -> try_decrypt_list(k_id, k_kind, keys, esk)
      {:ok, key} -> Pgpex.SessionKeyDecryptor.decrypt_session_key(k_kind, key, esk)
      {:error, e} -> {:error, {:no_matching_key, k_kind, k_id, e}}
    end
  end

  defp try_decrypt_list(k_id, _, [], _) do
    {:error, {:no_matching_key, k_id}}
  end

  defp try_decrypt_list(k_id, k_kind, keys, esk) do
    k_results = Enum.map(keys, fn(k) ->
      Pgpex.SessionKeyDecryptor.decrypt_session_key(k_kind, k, esk)
    end)
    k_oks = Enum.filter(k_results, fn({:ok, _}) -> true end)
    case Enum.any?(k_oks) do
      false -> {:error, {:no_matching_key, k_id}}
      _ -> {:ok, Enum.map(k_oks, fn({:ok, v}) -> v end)}
    end
  end

  defp read_encrypted_session_key({:rsa, _}, f) do
    Pgpex.Primitives.Mpi.read_mpi_bytes(f)
  end

  defp read_version_key_id_and_pk_algo(f) do
    case IO.binread(f, 10) do
      <<version::big-unsigned-integer-size(8),key_id::binary-size(8),pk_algo::big-unsigned-integer-size(8)>> -> {:ok, version, key_id, pk_algo}
      <<data::binary>> -> {:error,{:version_key_id_and_pk_algo_data_too_short, data}}
      :eof -> {:error,:version_key_id_and_pk_algo_data_eof}
      e -> {:error, {:version_key_id_and_pk_algo_data_read_error, e}}
    end
  end
end
