defmodule Pgpex.Packets.KeyPacket do
  def read_validity_and_algo(f) do
    case IO.binread(f, 3) do
      <<validity::big-unsigned-integer-size(16),algo::big-unsigned-integer-size(8)>> -> {:ok, validity, algo}
      <<data::binary>> -> {:error, {:read_validity_and_algo_error, data}}
      :eof -> {:error, :read_validity_and_algo_eof}
      a -> {:error, a}
    end
  end

  def read_algo(f) do
    case IO.binread(f, 1) do
      <<algo::big-unsigned-integer-size(8)>> -> {:ok, algo}
      :eof -> {:error, :read_algo_eof}
      a -> {:error, a}
    end
  end

  def read_version_and_k_time(f) do
    case IO.binread(f, 5) do
      <<ver::big-unsigned-integer-size(8),k_time::binary-size(4)>> -> {:ok, ver, k_time}
      <<data::binary>> -> {:error, {:key_version_and_time_data_too_sort, data}}
      :eof -> {:error, :key_version_and_time_eof}
      e -> {:error, {:key_version_and_time_read_error, e}}
    end
  end
end
