defmodule Pgpex.Primitives.MpiTest do
  use ExUnit.Case
  doctest Pgpex.Primitives.Mpi

  test "encodes 521 properly" do
    <<
      0::unsigned-big-integer-size(8),
      10::unsigned-big-integer-size(8),
      2::unsigned-big-integer-size(8),
      9::unsigned-big-integer-size(8)
    >> = Pgpex.Primitives.Mpi.encode_mpi(521)
  end

  test "encodes 520 properly" do
    <<
      0::unsigned-big-integer-size(8),
      1::unsigned-big-integer-size(8),
      1::unsigned-big-integer-size(8)
    >> = Pgpex.Primitives.Mpi.encode_mpi(1)
  end

  test "encodes binary 1 properly" do
    <<
      0::unsigned-big-integer-size(8),
      1::unsigned-big-integer-size(8),
      1::unsigned-big-integer-size(8)
    >> = Pgpex.Primitives.Mpi.encode_mpi(<<1::unsigned-big-integer-size(16)>>)
  end

  test "encodes binary 256 properly" do
    <<
      0::unsigned-big-integer-size(8),
      9::unsigned-big-integer-size(8),
      1::unsigned-big-integer-size(8),
      0::unsigned-big-integer-size(8)
    >> = Pgpex.Primitives.Mpi.encode_mpi(<<256::unsigned-big-integer-size(16)>>)
  end

  test "encodes binary 520 properly" do
    <<
      0::unsigned-big-integer-size(8),
      10::unsigned-big-integer-size(8),
      2::unsigned-big-integer-size(8),
      9::unsigned-big-integer-size(8)
    >> = Pgpex.Primitives.Mpi.encode_mpi(<<521::unsigned-big-integer-size(16)>>)
  end
end
