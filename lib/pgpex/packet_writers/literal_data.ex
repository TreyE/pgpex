defmodule Pgpex.PacketWriters.LiteralData do
  defstruct [
    io: nil,
    write_buffer: <<>>,
    header_written: false
  ]

  @formats %{
    :binary => 0x62,
    :text => 0x74,
    :utf8 => 0x75
  }

  def initialize(f, f_name, date, format \\ :binary) do
    first_bytes = construct_packet_info(f_name, date, format)
    packet_tag = Pgpex.PacketWriters.WriterUtils.new_format_tag(11)
    IO.binwrite(f, packet_tag)
    %__MODULE__{
      io: f,
      write_buffer: first_bytes
    }
  end

  def binwrite(%__MODULE__{} = w, new_data) do
    new_full_buff = w.write_buffer <> new_data
    {remaining_buff, h_written} = chomp_me(new_full_buff, w.io, w.header_written)
    {:ok, %__MODULE__{
      w |
        write_buffer: remaining_buff,
        header_written: h_written
    }}
  end

  def finalize(%__MODULE__{} = w) do
    bytes_to_write = w.write_buffer
    case w.header_written do
      false ->
        IO.binwrite(
          w.io,
          Pgpex.PacketWriters.WriterUtils.encode_new_format_len(byte_size(bytes_to_write))
        )
      _ -> :ok
    end
    IO.binwrite(w.io, bytes_to_write)
  end

  defp chomp_me(<<eatable::binary-size(512), rest::binary>>, f, _) do
    v_len = Pgpex.PacketWriters.WriterUtils.encode_new_format_varlen(512)
    IO.binwrite(
      f,
      v_len
    )
    IO.binwrite(
      f,
      eatable
    )
    chomp_me(rest, f, true)
  end

  defp chomp_me(<<left::binary>>, _, h_written) do
    {left, h_written}
  end

  defp construct_packet_info(f_name, date, format) do
    format_byte = Map.get(@formats, format, 0x62)
    f_name_bytes = Pgpex.Primitives.FileName.to_binary(f_name)
    date_bytes = Pgpex.Primitives.Time.to_binary(date)
    <<format_byte::big-unsigned-integer-size(8)>> <> f_name_bytes <> date_bytes
  end
end
