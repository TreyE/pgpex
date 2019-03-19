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
    Pgpex.PacketHeader.t()
    ) ::
      packet() |
      Pgpex.PacketHeader.t() |
      {:error, any()}
  def parse_packet(f, %Pgpex.PacketHeader{tag: :literal_data} = d) do
    Pgpex.Packets.LiteralData.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :compressed_data} = d) do
    Pgpex.Packets.CompressedData.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :symmetrically_encrypted_and_integrity_protected_data} = d) do
    Pgpex.Packets.SymmetricallyEncryptedAndIntegrityProtectedData.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :public_key_encrypted_session_key} = d) do
    Pgpex.Packets.PublicKeyEncryptedSessionKey.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :public_key} = d) do
    Pgpex.Packets.PublicKey.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :public_subkey} = d) do
    Pgpex.Packets.PublicKey.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :secret_key} = d) do
    Pgpex.Packets.SecretKey.parse(f, d)
  end

  def parse_packet(f, %Pgpex.PacketHeader{tag: :secret_subkey} = d) do
    Pgpex.Packets.SecretKey.parse(f, d)
  end

  def parse_packet(_, %Pgpex.PacketHeader{tag: {:invalid, _}} = header) do
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
      def parse_packet(_, %Pgpex.PacketHeader{tag: unquote(item)} = header) do
        header
      end
  end)
end
