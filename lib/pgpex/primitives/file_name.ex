defmodule Pgpex.Primitives.FileName do
  def to_binary(<<>>) do
    <<0::unsigned-big-integer-size(8)>>
  end

  def to_binary(nil) do
    <<0::unsigned-big-integer-size(8)>>
  end

  def to_binary(f_name) when  is_binary(f_name) and (byte_size(f_name) < 256) do
    b_size = byte_size(f_name)
    <<b_size::unsigned-big-integer-size(8)>> <> f_name
  end

  def to_binary(<<f_name::binary-size(252), _::binary>>) when  is_binary(f_name) do
    <<255::unsigned-big-integer-size(8)>> <> f_name <> "..."
  end
end
