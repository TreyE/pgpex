defmodule Pgpex.Packet do
  @type packet ::
    Pgpex.Packets.CompressedData.t() |
    Pgpex.Packets.LiteralData.t() |
    Pgpex.Packets.PublicKey.t() |
    Pgpex.Packets.PublicKeyEncryptedSessionKey.t() |
    Pgpex.Packets.SecretKey.t() |
    Pgpex.Packets.SymmetricallyEncryptedAndIntegrityProtectedData.t()

  @spec parse_packet(
    any(),
    Pgpex.PacketReader.packet_header()
    ) ::
      packet() |
      Pgpex.PacketReader.packet_header() |
      {:error, any()} |
      binary() |
      [byte()] |
      :eof
  def parse_packet(f, {:literal_data, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.LiteralData.parse(f, d)
  end

  def parse_packet(f, {:compressed_data, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.CompressedData.parse(f, d)
  end

  def parse_packet(f, {:symmetrically_encrypted_and_integrity_protected_data, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.SymmetricallyEncryptedAndIntegrityProtectedData.parse(f, d)
  end

  def parse_packet(f, {:public_key_encrypted_session_key, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.PublicKeyEncryptedSessionKey.parse(f, d)
  end

  def parse_packet(f, {:public_key, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.PublicKey.parse(f, d)
  end

  def parse_packet(f, {:public_subkey, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.PublicKey.parse(f, d)
  end

  def parse_packet(f, {:secret_key, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.SecretKey.parse(f, d)
  end

  def parse_packet(f, {:secret_subkey, packet_len, packet_indexes, data_len, data_indexes} = d) do
    Pgpex.Packets.SecretKey.parse(f, d)
  end

  def parse_packet(_, {{:invalid, _},_,_,_,_} = header) do
    header
  end

  Enum.map(
    [:reserved,
    :signature,
    :symmetric_key_encrypted_session,
    :one_pass_signature,
    :symmetrically_encrypted_data,
    :marker,
    :trust,
    :user_id,
    :user_attribute,
    :modification_detection_code,
    :private_or_experimental],
    fn(item) ->
      def parse_packet(_, {unquote(item),_,_,_,_} = header) do
        header
      end
  end)
end
