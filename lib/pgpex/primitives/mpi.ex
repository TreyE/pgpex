defmodule Pgpex.Primitives.Mpi do
  import Pgpex.Primitives.IOUtils
  require Bitwise

  def encode_mpi(<<>>) do
    <<
      1::unsigned-big-integer-size(16),
      0::unsigned-big-integer-size(8)
    >>
  end

  def encode_mpi(<<0::unsigned-big-integer-size(8),rest::binary>>) do
    encode_mpi(rest)
  end

  def encode_mpi(<<top_byte::unsigned-big-integer-size(8),_::binary>> = val) when is_binary(val) do
    bit_size = (byte_size(val) * 8) - shift_me_down(top_byte, 8)
    <<bit_size::unsigned-big-integer-size(16)>> <> val
  end

  def encode_mpi(0) do
    <<
    1::unsigned-big-integer-size(16),
    0::unsigned-big-integer-size(8)
    >>
  end

  def encode_mpi(num) do
    bits = mpi_int_bits(num)
    binary_bytes = div(bits + 7, 8) * 8
    <<
      bits::unsigned-big-integer-size(16),
      num::unsigned-big-integer-size(binary_bytes)
    >>
  end

  defp mpi_int_bits(num) do
    num
      |> Integer.digits(2)
      |> Enum.count
  end

  defp shift_me_down(0, n), do: n
  defp shift_me_down(v, n) do
    shift_me_down(div(v, 2), n - 1)
  end

  def read_mpi(f) do
    with ({:ok, mpi_len} <- read_mpi_size(f)) do
      mpi_bits = mpi_len + 7
      mpi_bytes = div(mpi_bits, 8)
      mpi_bit_size = mpi_bytes * 8
      with ({:ok, mpi_value_as_bytes} <- read_mpi_value_bytes(f, mpi_bytes)) do
        case mpi_value_as_bytes do
          <<mpi_val::big-unsigned-integer-size(mpi_bit_size)>> -> {:ok, mpi_val}
          _ -> {:error, {:mpi_conversion_error, mpi_bit_size, mpi_value_as_bytes}}
        end
      end
    end
  end

  def read_mpi_bytes(f) do
    with ({:ok, mpi_len} <- read_mpi_size(f)) do
      mpi_bits = mpi_len + 7
      mpi_bytes = div(mpi_bits, 8)
      read_mpi_value_bytes(f, mpi_bytes)
    end
  end

  defp read_mpi_size(f) do
    binread_match(f, 2, :read_mpi_length_eof, :invalid_mpi_size) do
      <<mpi_len::big-unsigned-integer-size(16)>> -> {:ok, mpi_len}
    end
  end

  defp read_mpi_value_bytes(f, mpi_bytes) do
    binread_match(f, mpi_bytes, :read_mpi_bytes_eof, :read_mpi_bytes_error) do
      <<a::binary-size(mpi_bytes)>> -> {:ok, a}
    end
  end
end
