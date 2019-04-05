defmodule Pgpex.Primitives.Mpi do
  import Pgpex.Primitives.IOUtils

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
