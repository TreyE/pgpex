defmodule Pgpex.Primitives.Time do
  @spec to_binary(
      Calendar.datetime()
      | integer()
      | binary()
    ) :: binary()
  def to_binary(utc_timestamp) when is_integer(utc_timestamp) do
    encode_binary_int(utc_timestamp)
  end

  def to_binary(%{utc_offset: _, std_offset: _} = datetime) do
    int_val = DateTime.to_unix(datetime, :second)
    encode_binary_int(int_val)
  end

  def to_binary(v) when is_binary(v), do: v

  defp encode_binary_int(int_val) do
    <<int_val::big-unsigned-integer-size(32)>>
  end
end
