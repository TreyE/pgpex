defmodule Pgpex.Packets.PublicKeyEncryptedSessionKey do
  @type t :: {:public_key_encrypted_session_key, any(), binary(), key_kind(), binary()}
  @type key_kind :: {:rsa, :both} | {:rsa, :encrypt} | {:rsa, :sign}

  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  @spec parse(
          any(),
          any()
        ) ::
          {:error,
             atom()
             | {:version_key_id_and_pk_algo_data_read_error,
                atom() | {:no_translation, :unicode, :latin1}}
             | {:version_key_id_and_pk_algo_data_too_short, binary()}
             | {:no_translation, :unicode, :latin1}}
          | t()
  def parse(f, {:public_key_encrypted_session_key, _packet_len, _packet_indexes, _data_len, {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, version, key_id, pk_algo} <- read_version_key_id_and_pk_algo(f),
         key_kind = Map.get(@pk_algo_identifiers, pk_algo, {:unknown, :unknown}),
         {:ok, encrypted_session_key} <- read_encrypted_session_key(key_kind, f) do
      {:public_key_encrypted_session_key, version, key_id, key_kind, encrypted_session_key}
    end
  end

  defp read_encrypted_session_key({:rsa, _}, f) do
    Pgpex.Primatives.Mpi.read_mpi_bytes(f)
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
