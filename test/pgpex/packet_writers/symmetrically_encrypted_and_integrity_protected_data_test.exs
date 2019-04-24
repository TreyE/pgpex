defmodule Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedDataTest do
  use ExUnit.Case
  use Bitwise
  doctest Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedData

  test "can encrypt a random aes-256 session key based packet" do
    f_name = "test/test_data/test_encrypting_session_data.bin"
    {:ok, written_message_file} = :file.open(f_name, [:write, :binary])
    k = read_rsa_public_sub_key_packet()
    pk_algo_identifier = {k.algo_type, k.usage}
    key_bytes = :crypto.strong_rand_bytes(32)
    {:ok, packet} = Pgpex.PacketWriters.PublicKeyEncryptedSessionKey.construct_packet(
      pk_algo_identifier,
      k.public_key,
      :aes_256,
      key_bytes,
      <<0xE8D33E0C19F4F674::unsigned-big-integer-size(64)>>)
    IO.binwrite(written_message_file, packet)

    the_test_string = """
    SOME REALLY LONG STRING THAT I WANT YOU TO TRY AND READ
    """
    w_1 = Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedData.initialize(
      {:aes, key_bytes},
      written_message_file
    )
    out_pid = Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedData.wrap_as_file(w_1)
    ld = Pgpex.PacketWriters.LiteralData.initialize(out_pid, "A FILE NAME", 0)
    {:ok, ld_2} = Pgpex.PacketWriters.LiteralData.binwrite(ld, the_test_string)
    Pgpex.PacketWriters.LiteralData.finalize(ld_2)
    {:ok, w_2} = Pgpex.Primitives.Behaviours.WritableFile.unwrap(out_pid)
    Pgpex.PacketWriters.SymmetricallyEncryptedAndIntegrityProtectedData.finalize(
      w_2
    )
    :file.close(written_message_file)
    {:ok, f} = :file.open(f_name, [:read, :binary])
    {:ok, headers} = Pgpex.PacketReader.read_headers(f)
    p_results = Enum.map(headers, fn(h) ->
      Pgpex.Packet.parse_packet(f, h)
    end)
    pkesk = Enum.at(p_results, 0)
    key_provider = fn(_,_) ->
      {:ok, [read_rsa_priv_key()]}
    end
    {:ok, [decrypted_session_key]} = Pgpex.Packets.PublicKeyEncryptedSessionKey.decrypt_session_key(pkesk, key_provider)
    {:ok, :aes_256, ^key_bytes} = (Pgpex.Primitives.SessionKey.decode_session_key(decrypted_session_key))
    op = Enum.at(p_results, 1)
    [{ds, _}|_] = op.data_indexes
    :ok = Pgpex.SessionDecryptors.Aes.read_and_verify_first_block(op.io, ds, key_bytes)
    {:ok, _} = Pgpex.SessionDecryptors.Aes.verify_mdc(op.io, key_bytes, op.data_length, op.data_indexes)
    session_reader = Pgpex.SessionDecryptors.Aes.create_session_reader(
      op.io,
      key_bytes,
      op.data_length,
      op.data_indexes
    )
    readable_session_data = Pgpex.Primitives.Behaviours.ReadableFile.wrap_as_file(
      Pgpex.SessionDecryptors.AesSessionStream,
      session_reader
    )
    {:ok, new_headers} = Pgpex.PacketReader.read_headers(readable_session_data)
    new_p_results = Enum.map(new_headers, fn(h) ->
      Pgpex.Packet.parse_packet(readable_session_data, h)
    end)
    lit_packet = Enum.at(new_p_results, 0)
    lit_packet_reader = Pgpex.Primitives.SkipFileReader.wrap_as_file(lit_packet.reader)
    ^the_test_string = IO.binread(lit_packet_reader, :all)
    :file.close(readable_session_data)
    :file.close(f)
    File.rm!(f_name)
  end

  defp read_rsa_public_sub_key_packet() do
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

    pub_key = Enum.at(all_entries, 0)
    Enum.at(pub_key, 3)
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
