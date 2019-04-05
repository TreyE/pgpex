defmodule Pgpex.Primitives.Crc24Test do
  use ExUnit.Case
  doctest Pgpex.Primitives.Crc24

  test "simple crc check" do
     crc24_test("a", 0xf25713)
  end

  test "longer crc check" do
    crc24_test("abc", 0xba1c7b)
  end

  test "very long crc check" do
    crc24_test(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      0x4662cd
    )
  end

  defp crc24_test(input, expected) do
    register = Pgpex.Primitives.Crc24.init_register
    <<0::unsigned-big-integer-size(24)>> = (
      register
        |> Pgpex.Primitives.Crc24.add(input)
        |> Pgpex.Primitives.Crc24.add(<<expected::unsigned-big-integer-size(24)>>)
    )
  end

end
