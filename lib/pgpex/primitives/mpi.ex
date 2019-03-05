defmodule Pgpex.Primatives.Mpi do
  def read_mpi(f) do
    with (<<mpi_len::big-unsigned-integer-size(16)>> <- IO.binread(f, 2)) do
      mpi_bits = mpi_len + 7
      mpi_bytes = div(mpi_bits, 8)
      mpi_bit_size = mpi_bytes * 8
      with (<<mpi_val::big-unsigned-integer-size(mpi_bit_size)>> <- IO.binread(f, mpi_bytes)) do
        {:ok, mpi_val}
      end
    end
  end

  def read_mpi_bytes(f) do
    with (<<mpi_len::big-unsigned-integer-size(16)>> <- IO.binread(f, 2)) do
      mpi_bits = mpi_len + 7
      mpi_bytes = div(mpi_bits, 8)
      with (<<mpi_val::binary>> <- IO.binread(f, mpi_bytes)) do
        {:ok, mpi_val}
      end
    end
  end
end
