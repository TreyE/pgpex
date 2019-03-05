defmodule Pgpex.Primitives.SessionKey do
  @session_key_algos %{
    9 => :aes_256
  }

  def decode_session_key(data) when is_binary(data) do
    <<algo::integer-unsigned-big-size(8),rest::binary>> = data
    <<checksum::big-integer-unsigned-size(16)>> = :binary.part(rest, byte_size(rest) - 2, 2)
    key_data = :binary.part(rest, 0, byte_size(rest) - 2)
    case byte_by_byte_checksum(key_data, 0) do
      ^checksum -> resolve_session_key_algo(algo, key_data)
      a -> {:error, {:checksum_mismatch, checksum, a}}
    end
  end

  defp resolve_session_key_algo(algo, key_data) do
    case Map.has_key?(@session_key_algos, algo) do
      true -> {:ok, Map.fetch!(@session_key_algos, algo), key_data}
      false -> {:error, {:unknown_session_key_algo, algo, key_data}}
    end
  end

  defp byte_by_byte_checksum(<<>>, total) do
    rem(total, 65536)
  end

  defp byte_by_byte_checksum(<<b::big-unsigned-integer-size(8),rest::binary>>, total) do
    byte_by_byte_checksum(rest, b + total)
  end
end
