defmodule Pgpex.Packets.PublicKeyEncryptedSessionKeyTest do
  use ExUnit.Case
  use Bitwise
  doctest Pgpex.Packets.PublicKeyEncryptedSessionKey

  test "it can decrypt the private key in a simple message" do
    f_name = "test/test_data/simple_message.asc"
    {:ok, f} = :file.open(f_name, [:read, :binary])

    entries = Enum.map(Pgpex.Armor.Reader.initialize(f), fn({:ok, {a,b,c}}) ->
      {:ok, new_reader} = Pgpex.Armor.B64StreamReader.reopen_as_new_file(c, f_name)
      {a, b, new_reader}
    end)
    :file.close(f)
    parsed_files = Enum.map(entries, fn({_, _, c}) ->
      :file.position(c, :bof)
      {:ok, result} = Pgpex.PacketReader.read_headers(c)

      Enum.map(result, fn(h) ->
        Pgpex.Packet.parse_packet(c, h)
      end)
    end)
    [first_message|_] = parsed_files
    [%Pgpex.Packets.PublicKeyEncryptedSessionKey{key_kind: {:rsa, :both}, encrypted_session_key: packet_data},op] = first_message
    priv_key = read_rsa_priv_key()
    decrypted_session_key = :public_key.decrypt_private(packet_data, priv_key, [{:rsa_padding, :rsa_no_padding}])
    {:ok, :aes_256, key} = (Pgpex.Primitives.SessionKey.decode_session_key(decrypted_session_key))
    [{ds, _}|_] = op.data_indexes
    :ok = Pgpex.SessionDecryptors.Aes.read_and_verify_first_block(op.io, ds, key)
    {:ok, _} = Pgpex.SessionDecryptors.Aes.verify_mdc(op.io, key, op.data_length, op.data_indexes)
    session_reader = Pgpex.SessionDecryptors.Aes.create_session_reader(
      op.io,
      key,
      op.data_length,
      op.data_indexes
    )
    readable_session_data = Pgpex.Primitives.Behaviours.ReadableFile.wrap_as_file(
      Pgpex.SessionDecryptors.AesSessionStream,
      session_reader
    )
    {:ok, [compressed_packet|_]} = Pgpex.PacketReader.read_headers(readable_session_data)
    compressed_packet_data = Pgpex.Packet.parse_packet(readable_session_data, compressed_packet)
    {:ok, reader_stream} = Pgpex.Packets.CompressedData.create_reader(compressed_packet_data)
    f_reader_stream = reader_stream.__struct__.wrap_as_file(reader_stream)
    {:ok, decrypted_packet_data} = Pgpex.PacketReader.read_headers(f_reader_stream)
    [lit_packet|_] = Enum.map(decrypted_packet_data, fn(pd) ->
      Pgpex.Packet.parse_packet(f_reader_stream, pd)
    end)
    "mix.exs" = lit_packet.file_name
    {:ok, _, "defmodule Pgpex.MixProject do"} = Pgpex.Primitives.SkipFileReader.binread(lit_packet.reader, 29)
  end

  defp read_rsa_priv_key() do
    f_name = "test/test_data/pub_and_private_key.asc"
    {:ok, f} = :file.open(f_name, [:read, :binary])

    entries = Enum.map(Pgpex.Armor.Reader.initialize(f), fn({:ok, {a,b,c}}) ->
      {:ok, new_reader} = Pgpex.Armor.B64StreamReader.reopen_as_new_file(c, f_name)
      {a, b, new_reader}
    end)
    :file.close(f)
    all_entries = Enum.map(entries, fn({_, _, c}) ->
      :file.position(c, :bof)
      {:ok, result} = Pgpex.PacketReader.read_headers(c)

      Enum.map(result, fn(h) ->
        Pgpex.Packet.parse_packet(c, h)
      end)
    end)

    priv_key = Enum.at(all_entries, 1)
    rsa_priv_packet = Enum.at(priv_key, 3)
    %Pgpex.Packets.SecretKey{tag: :secret_subkey, version: 4, key_time: <<92, 121, 129, 46>>, algo_type: :rsa, usage: :both, secret_key: rsa_priv_key} = rsa_priv_packet
    rsa_priv_key
  end
end
