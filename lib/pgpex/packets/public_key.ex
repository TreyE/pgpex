defmodule Pgpex.Packets.PublicKey do
  @type t :: %__MODULE__{
    tag: tag(),
    version: 3,
    public_key: any(),
    usage: usage(),
    algo_type: algo_type(),
    validity: binary(),
    key_time: binary()
  } |
  %__MODULE__{
    tag: tag(),
    version: 4,
    public_key: any(),
    usage: usage(),
    algo_type: algo_type(),
    validity: nil,
    key_time: binary()
  }
  @type tag :: :public_key | :public_subkey
  @type usage :: :encrypt | :sign | :both
  @type algo_type :: :rsa

  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  defstruct [
    version: 4,
    tag: :public_key,
    usage: :encrypt,
    algo_type: :rsa,
    key_time: nil,
    public_key: nil,
    validity: nil
  ]

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
             | {:unsupported_packet_version, :public_key | :public_subkey, byte()}}
          | t()
  def parse(f, {:public_key, _packet_len, _packet_indexes, data_len, {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- Pgpex.Packets.KeyPacket.read_version_and_k_time(f) do
      read_packet(:public_key, f, ver, k_time, data_len - 5)
    end
  end

  def parse(f, {:public_subkey, _packet_len, _packet_indexes, data_len, {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- Pgpex.Packets.KeyPacket.read_version_and_k_time(f) do
      read_packet(:public_subkey, f, ver, k_time, data_len - 5)
    end
  end

  defp read_packet(tag, f, 3, k_time, len_left) do
    with {:ok, validity, algo} <- Pgpex.Packets.KeyPacket.read_validity_and_algo(f),
         {algo_type, usage} = Map.get(@pk_algo_identifiers, algo, {:unknown, :unknown}),
         {:ok, key_data} <- read_key_data(f, algo, len_left - 3) do
      %__MODULE__{
        tag: tag,
        version: 3,
        validity: validity,
        usage: usage,
        algo_type: algo_type,
        key_time: k_time,
        public_key: key_data
      }
    end
  end

  defp read_packet(tag,  f, 4, k_time, len_left) do
    with {:ok, algo} <- Pgpex.Packets.KeyPacket.read_algo(f),
         {algo_type, usage} = Map.get(@pk_algo_identifiers, algo, {:unknown, :unknown}),
         {:ok, key_data} <- read_key_data(f, algo_type, len_left - 1) do
      %__MODULE__{
        tag: tag,
        version: 4,
        usage: usage,
        algo_type: algo_type,
        key_time: k_time,
        public_key: key_data
      }
    end
  end

  defp read_packet(tag, _, v, _, _) do
    {:error, {:unsupported_packet_version, tag, v}}
  end

  defp read_key_data(f, :rsa, _) do
    with {:ok, m} <- Pgpex.Primatives.Mpi.read_mpi(f),
         {:ok, e} <- Pgpex.Primatives.Mpi.read_mpi(f) do
      {:ok, create_rsa_public_key_record(m, e)}
    end
  end

  defp read_key_data(_, k_type, _) do
    {:error, {:unsupported_key_type, k_type}}
  end

  defp create_rsa_public_key_record(m, e) do
    {:'RSAPublicKey', m, e}
  end
end
