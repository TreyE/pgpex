defmodule Pgpex.Packets.PublicKey do
  @pk_algo_identifiers %{
    1 => {:rsa, :both},
    2 => {:rsa, :encrypt},
    3 => {:rsa, :sign}
  }

  def parse(f, {:public_key, packet_len, packet_indexes, data_len, {d_start, d_end}} = d) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- read_version_and_k_time(f) do
      read_packet(:public_key, f, ver, k_time, data_len - 5)
    end
  end

  def parse(f, {:public_subkey, packet_len, packet_indexes, data_len, {d_start, d_end}} = d) do
    with {:ok, _} <- :file.position(f, d_start),
         {:ok, ver, k_time} <- read_version_and_k_time(f) do
      read_packet(:public_subkey, f, ver, k_time, data_len - 5)
    end
  end

  defp read_packet(tag, f, 3, k_time, len_left) do
    with (<<validity::big-unsigned-integer-size(16),algo::big-unsigned-integer-size(8)>> <- IO.binread(f, 3)) do
      {algo_type, usage} = Map.get(@pk_algo_identifiers, algo, {:unknown, :unknown})
      {tag, 3, k_time, validity, algo_type, usage}
    end
  end

  defp read_packet(tag,  f, 4, k_time, len_left) do
    with <<algo::big-unsigned-integer-size(8)>> <- IO.binread(f, 1),
         {algo_type, usage} = Map.get(@pk_algo_identifiers, algo, {:unknown, :unknown}),
         {:ok, key_data} <- read_key_data(f, algo_type, len_left - 1) do
      {tag, 4, k_time, algo_type, usage, key_data}
    end
  end

  defp read_packet(tag, _, v, _, _) do
    {:error, {:unsupported_packet_version, tag, v}}
  end

  defp read_key_data(f, :rsa, _) do
    with {:ok, m} <- read_mpi(f),
         {:ok, e} <- read_mpi(f) do
      {:ok, create_rsa_public_key_record(m, e)}
    end
  end

  defp read_key_data(_, k_type, _) do
    {:error, {:unsupported_key_type, k_type}}
  end

  defp read_mpi(f) do
    with (<<mpi_len::big-unsigned-integer-size(16)>> <- IO.binread(f, 2)) do
      mpi_bits = mpi_len + 7
      mpi_bytes = div(mpi_bits, 8)
      mpi_bit_size = mpi_bytes * 8
      with (<<mpi_val::big-unsigned-integer-size(mpi_bit_size)>> <- IO.binread(f, mpi_bytes)) do
        {:ok, mpi_val}
      end
    end
  end

  defp read_version_and_k_time(f) do
    case IO.binread(f, 5) do
      <<ver::big-unsigned-integer-size(8),k_time::binary-size(4)>> -> {:ok, ver, k_time}
      <<data::binary>> -> {:error, {:key_version_and_time_data_too_sort, data}}
      :eof -> {:error, :key_version_and_time_eof}
      {:error, e} -> {:error, {:key_version_and_time_read_error, e}}
    end
  end

  defp create_rsa_public_key_record(m, e) do
    {:'RSAPublicKey', m, e}
  end
end
