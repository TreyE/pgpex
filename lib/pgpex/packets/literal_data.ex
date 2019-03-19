defmodule Pgpex.Packets.LiteralData do

  @type t :: %__MODULE__{}

  @formats %{
    0x62 => :binary,
    0x74 => :text,
    0x75 => :utf8
  }

  defstruct [
    reader: nil,
    io: nil,
    packet_length: 0,
    packet_indexes: [],
    data_length: 0,
    positions: [],
    format: :binary,
    data_date: nil,
    file_name: nil
  ]

  import Pgpex.Primatives.IOUtils

  @spec parse(
          any(),
          Pgpex.PacketHeader.t(:literal_data)
        )  ::
        {:error, any()}
        | t()
  def parse(f, %Pgpex.PacketHeader{tag: :literal_data, packet_length: packet_len, packet_locations: packet_indexes, data_length: data_len, data_locations: positions}) do
    with {file_start, data_length, data_positions} <- data_indexes(data_len, positions),
         {:ok, format} <- read_format(f, file_start),
         {:ok, file_name, date, lit_len, lit_pos} <- read_file_name_and_data_date(f, data_length, data_positions) do
      skr = Pgpex.Primatives.SkipFileReader.new(f, lit_len, lit_pos)
      %__MODULE__{
        io: f,
        packet_length: packet_len,
        packet_indexes: packet_indexes,
        data_length: lit_len,
        positions: lit_pos,
        format: format,
        reader: skr,
        data_date: date,
        file_name: file_name
      }
    end
  end

  defp read_format(f, file_start) do
    with ({:ok, _} <- :file.position(f, file_start)) do
      case IO.binread(f,1) do
        <<data::big-unsigned-integer-size(8)>> -> {:ok, Map.get(@formats, data, {:unknown, data})}
        :eof -> {:error, :eof_while_reading_compression_algo}
        a -> {:error, a}
      end
    end
  end

  defp read_file_name_and_data_date(f, d_len, [{s_start, s_end}|others]) do
     with {:ok, fn_len} <- read_fn_len(f),
          {:ok, f_name} <- read_fname(f, fn_len),
          {:ok, date} <- read_date(f) do
        {:ok, f_name, date, d_len - 5 - fn_len, [{s_start + 5 + fn_len,s_end}|others]}
     end
  end

  defp read_fname(f, fname_len) do
    case IO.binread(f,fname_len) do
      <<f_name::binary-size(fname_len)>> -> {:ok, f_name}
      <<invalid_data::binary>> -> {:error, {:file_name_read_too_short, invalid_data}}
      :eof -> {:error, :file_name_read_eof}
      a -> {:error, a}
    end
  end


  defp read_fn_len(f) do
    binread_match(f, 1, :file_name_length_read_eof, :file_name_length_invalid) do
      <<fn_len::unsigned-big-integer-size(8)>> -> {:ok, fn_len}
    end
  end

  defp read_date(f) do
    binread_match(f, 4, :date_read_eof, :date_invalid) do
      <<date::binary-size(4)>> -> {:ok, date}
    end
  end



  defp data_indexes(length, {s_pos, e_pos}) do
    {s_pos, length - 1, [{s_pos + 1, e_pos}]}
  end

  defp data_indexes(length, [{s_pos, e_pos}|others]) do
    {s_pos, length - 1, [{s_pos + 1, e_pos}|others]}
  end
end
