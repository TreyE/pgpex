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

  import Pgpex.Primitives.IOUtils
  use Bitwise

  @spec parse(
          any(),
          Pgpex.PacketHeader.t(:secret_key | :secret_subkey)
          ) ::
          {:error,
             atom()
             | {:key_version_and_time_data_too_sort, binary()}
             | {:key_version_and_time_read_error, atom() | {:no_translation, :unicode, :latin1}}
             | {:unsupported_key_type, any()}
             | {:no_translation, :unicode, :latin1}
             | {:unsupported_packet_version, :secret_key | :secret_subkey, byte()}}
          | t()
  def parse(f, %Pgpex.PacketHeader{tag: :secret_key, data_length: data_len, data_locations: {d_start, _d_end}}) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- Pgpex.Packets.KeyPacket.read_version_and_k_time(f) do
      read_packet(:secret_key, f, ver, k_time, data_len - 5)
    end
  end

  def parse(f, %Pgpex.PacketHeader{tag: :secret_subkey, data_length: data_len, data_locations: {d_start, _d_end}}) do
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

  defp read_key_data(f, :rsa, l_left) do
    with {:ok, c_pos} <- :file.position(f, :cur),
         {:ok, m} <- Pgpex.Primitives.Mpi.read_mpi(f),
         {:ok, e} <- Pgpex.Primitives.Mpi.read_mpi(f),
         {:ok, s2k} <- Pgpex.Primitives.S2K.RSASecretKey.read_rsa_s2k(f),
         {:ok, n_pos} <- :file.position(f, :cur) do
      process_rsa_key_data(s2k, m, e, f, l_left - (n_pos - c_pos))
    end
  end

  defp process_rsa_key_data(:unencrypted, m, e, f, _) do
    with ({:ok, d, p, q, u} <- read_rsa_plain_secret_key(f)) do
      {:ok, create_rsa_private_key_record(m, e, d, p, q, u)}
    end
  end

  defp process_rsa_key_data(:s2k_specifier_sha1, m, e, f, l_left) do
    with {:ok, c_pos} <- :file.position(f, :cur),
         s2k_rec = Pgpex.Primitives.S2K.RSASecretKey.new(m, e),
         {:ok, s2k_rec_with_algo} <- Pgpex.Primitives.S2K.RSASecretKey.read_s2k_algo(s2k_rec, f),
         {:ok, s2k_rec_with_s2k_specifier} <- Pgpex.Primitives.S2K.RSASecretKey.read_s2k_specifier(s2k_rec_with_algo, f),
         {:ok, n_pos} <- :file.position(f, :cur) do
      Pgpex.Primitives.S2K.RSASecretKey.process_s2k_parts(s2k_rec_with_s2k_specifier,f,l_left - (n_pos - c_pos))
    end
  end

  defp process_rsa_key_data(:s2k_specifier_csum, m, e, f, l_left) do
    with {:ok, c_pos} <- :file.position(f, :cur),
         s2k_rec = Pgpex.Primitives.S2K.RSASecretKey.new(m, e, :csum),
         {:ok, s2k_rec_with_algo} <- Pgpex.Primitives.S2K.RSASecretKey.read_s2k_algo(s2k_rec, f),
         {:ok, s2k_rec_with_s2k_specifier} <- Pgpex.Primitives.S2K.RSASecretKey.read_s2k_specifier(s2k_rec_with_algo, f),
         {:ok, n_pos} <- :file.position(f, :cur) do
      Pgpex.Primitives.S2K.RSASecretKey.process_s2k_parts(s2k_rec_with_s2k_specifier,f,l_left - (n_pos - c_pos))
    end
  end

  defp process_rsa_key_data(a, _, _, _, _) do
    {:error, {:unsupported_secret_key_s2k, a}}
  end

  def process_s2k_data(s_algo,h_algo,_,_,_,_,_,_) do
    {:error, {:unsupported_secret_key_s2k_algo_pairing, s_algo, h_algo}}
  end

  defp read_rsa_plain_secret_key(f) do
    with {:ok, d} <- Pgpex.Primitives.Mpi.read_mpi(f),
         {:ok, p} <- Pgpex.Primitives.Mpi.read_mpi(f),
         {:ok, q} <- Pgpex.Primitives.Mpi.read_mpi(f),
         {:ok, u} <- Pgpex.Primitives.Mpi.read_mpi(f) do
      {:ok, d, p, q, u}
    end
  end

  defp create_rsa_private_key_record(m, e, d, p, q, u) do
    {:'RSAPrivateKey', 1, m, e, d, p, q, rem(d, p - 1), rem(d, q - 1), u, :asn1_NOVALUE}
  end
end
