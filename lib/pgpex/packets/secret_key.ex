defmodule Pgpex.Packets.SecretKey do
  @type t :: v3_packet | v4_packet
  @type v3_packet :: %__MODULE__{
    tag: tag(),
    version: 3,
    algo_type: algo(),
    usage: usage(),
    validity: binary(),
    key_time: binary(),
    secret_key: any()
  }
  @type v4_packet :: %__MODULE__{
    tag: tag(),
    version: 4,
    algo_type: algo(),
    usage: usage(),
    validity: nil,
    key_time: binary(),
    secret_key: any()
  }
  @type tag :: :secret_key | :secret_subkey

  @type algo :: :rsa
  @type usage :: :encrypt | :sign | :both

  defstruct [
    tag: :public_key,
    version:  4,
    algo_type: :rsa,
    usage: :both,
    secret_key: nil,
    validity: nil,
    key_time: nil
  ]

  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  import Pgpex.Primatives.IOUtils

  @spec parse(
          any(),
          Pgpex.PacketReader.packet_header()
          ) ::
          {:error,
             atom()
             | {:key_version_and_time_data_too_sort, binary()}
             | {:key_version_and_time_read_error, atom() | {:no_translation, :unicode, :latin1}}
             | {:unsupported_key_type, any()}
             | {:no_translation, :unicode, :latin1}
             | {:unsupported_packet_version, :secret_key | :secret_subkey, byte()}}
          | t()
  def parse(f, {:secret_key, _packet_len, _packet_indexes, data_len, {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- Pgpex.Packets.KeyPacket.read_version_and_k_time(f) do
      read_packet(:secret_key, f, ver, k_time, data_len - 5)
    end
  end

  def parse(f, {:secret_subkey, _packet_len, _packet_indexes, data_len, {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- Pgpex.Packets.KeyPacket.read_version_and_k_time(f) do
      read_packet(:secret_subkey, f, ver, k_time, data_len - 5)
    end
  end

  defp read_packet(tag, f, 3, k_time, len_left) do
    with {:ok, validity, algo} <- Pgpex.Packets.KeyPacket.read_validity_and_algo(f),
         {algo_type, usage} = Map.get(@pk_algo_identifiers, algo, {:unknown, :unknown}),
         {:ok, key_data} <- read_key_data(f, algo_type, len_left - 1) do
      %__MODULE__{
        tag: tag,
        version: 3,
        key_time: k_time,
        algo_type: algo_type,
        usage: usage,
        validity: validity,
        secret_key: key_data
      }
    end
  end

  defp read_packet(tag, f, 4, k_time, len_left) do
    with {:ok, algo} <- Pgpex.Packets.KeyPacket.read_algo(f),
      {algo_type, usage} = Map.get(@pk_algo_identifiers, algo, {:unknown, :unknown}),
      {:ok, key_data} <- read_key_data(f, algo_type, len_left - 1) do
      %__MODULE__{
        tag: tag,
        version: 4,
        key_time: k_time,
        algo_type: algo_type,
        usage: usage,
        secret_key: key_data
      }
    end
  end

  defp read_packet(tag, _, v, _, _) do
    {:error, {:unsupported_packet_version, tag, v}}
  end

  defp read_key_data(f, :rsa, _) do
    with {:ok, m} <- Pgpex.Primatives.Mpi.read_mpi(f),
         {:ok, e} <- Pgpex.Primatives.Mpi.read_mpi(f),
         {:ok, d, p, q, u} <- read_rsa_secret_key_data(f) do
      {:ok, create_rsa_private_key_record(m, e, d, p, q, u)}
    end
  end

  defp read_key_data(_, k_type, _) do
    {:error, {:unsupported_key_type, k_type}}
  end

  defp read_rsa_secret_key_data(f) do
    binread_match(f, 1, :read_secret_key_version_eof, :unsupported_secret_key_s2k) do
      <<0::big-unsigned-integer-size(8)>> ->
        with {:ok, d} <- Pgpex.Primatives.Mpi.read_mpi(f),
             {:ok, p} <- Pgpex.Primatives.Mpi.read_mpi(f),
             {:ok, q} <- Pgpex.Primatives.Mpi.read_mpi(f),
             {:ok, u} <- Pgpex.Primatives.Mpi.read_mpi(f) do
          {:ok, d, p, q, u}
        end
    end
  end

  defp create_rsa_private_key_record(m, e, d, p, q, u) do
    {:'RSAPrivateKey', 1, m, e, d, p, q, rem(d, p - 1), rem(d, q - 1), u, :asn1_NOVALUE}
  end
end
