defmodule Pgpex.Packets.SymmetricallyEncryptedAndIntegrityProtectedData do
  @type t :: %__MODULE__{}

  defstruct [
    version: 1,
    packet_length: 0,
    packet_indexes: nil,
    data_length: 0,
    data_indexes: [],
    io: nil
  ]

  @spec parse(
          any(),
          Pgpex.PacketHeader.t(:symmetrically_encrypted_and_integrity_protected_data)
        ) ::
          {:error,
           atom()
           | {:packet_version_read_error,
              binary() | [byte()] | {:error, atom() | {any(), any(), any()}}}
           | {:unsupported_packet_version, binary()}}
          | Pgpex.Packets.SymmetricallyEncryptedAndIntegrityProtectedData.t()
  def parse(f, %Pgpex.PacketHeader{tag: :symmetrically_encrypted_and_integrity_protected_data, packet_length: packet_len, packet_locations: packet_indexes, data_length: data_len, data_locations: p_indexes}) do
    with({:ok, version, dis} <- read_version(f, p_indexes))do
      %__MODULE__{
        version: version,
        packet_length: packet_len,
        packet_indexes: packet_indexes,
        data_length: data_len - 1,
        data_indexes: dis,
        io: f
      }
    end
  end

  defp read_version(f, {d_start, d_end}) do
    read_version_at(f, d_start, [{d_start + 1, d_end}])
  end

  defp read_version(f, [{d_start, d_end}|other_dis]) do
    read_version_at(f, d_start, [{d_start + 1, d_end}|other_dis])
  end

  defp read_version_at(f, d_start, dis) do
    with({:ok, _} <- :file.position(f, d_start)) do
      case IO.binread(f, 1) do
        <<1::big-unsigned-integer-size(8)>> -> {:ok, 1, dis}
        <<data::binary>> -> {:error, {:unsupported_packet_version, data}}
        :eof -> {:error, :packet_version_read_eof}
        a -> {:error, {:packet_version_read_error, a}}
      end
    end
  end
end
