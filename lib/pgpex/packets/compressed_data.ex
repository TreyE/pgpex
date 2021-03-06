defmodule Pgpex.Packets.CompressedData do
  @type t :: %__MODULE__{}

  @compression_algos %{
    0 => :none,
    1 => :zip,
    2 => :zlib,
    3 => :bzip2
  }

  defstruct [
    io: nil,
    packet_length: 0,
    packet_indexes: [],
    data_length: 0,
    positions: [],
    algo: nil,
    reader: nil
  ]

  @spec parse(
          any(),
          Pgpex.PacketHeader.t(:compressed_data)
        ) ::
          {:error,
           atom() | binary() | [byte()] | {:error, atom() | {:no_translation, :unicode, :latin1}}}
          | Pgpex.Packets.CompressedData.t()
  def parse(f, %Pgpex.PacketHeader{tag: :compressed_data, packet_length: packet_len, packet_locations: packet_indexes, data_length: data_len, data_locations: positions}) do
    with {file_start, data_length, data_positions} <- data_indexes(data_len, positions),
         {:ok, read_algo} <- read_algo(f, file_start) do
      skr = Pgpex.Primitives.SkipFileReader.new(f, data_length, data_positions)
      %__MODULE__{
        io: f,
        packet_length: packet_len,
        packet_indexes: packet_indexes,
        data_length: data_length,
        positions: data_positions,
        algo: read_algo,
        reader: skr
      }
    end
  end

  defp data_indexes(length, {s_pos, e_pos}) do
   {s_pos, length - 1, [{s_pos + 1, e_pos}]}
  end

  defp data_indexes(length, [{s_pos, e_pos}|others]) do
    {s_pos, length - 1, [{s_pos + 1, e_pos}|others]}
  end

  defp read_algo(f, file_start) do
    with ({:ok, _} <- :file.position(f, file_start)) do
      case IO.binread(f,1) do
        <<data::big-unsigned-integer-size(8)>> -> {:ok, Map.get(@compression_algos, data, {:unknown, data})}
        :eof -> {:error, :eof_while_reading_compression_algo}
        a -> {:error, a}
      end
    end
  end

  def create_reader(%__MODULE__{algo: :zlib, reader: skr}) do
    Pgpex.Primitives.ZlibStream.create_reader_stream(skr)
  end

  def create_reader(%__MODULE__{algo: a}) do
    {:error, {:unsupported_compressed_data_algo, a}}
  end

end
