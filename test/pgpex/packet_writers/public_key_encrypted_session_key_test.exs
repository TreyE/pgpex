defmodule Pgpex.PacketWriters.PublicKeyEncryptedSessionKeyTest do
  use ExUnit.Case
  use Bitwise
  doctest Pgpex.PacketWriters.PublicKeyEncryptedSessionKey

  test "can encrypt a random aes-256 session key" do
    k = read_rsa_public_sub_key_packet()
    pk_algo_identifier = {k.algo_type, k.usage}
    key_bytes = :crypto.strong_rand_bytes(16)
    {:ok, packet} = Pgpex.PacketWriters.PublicKeyEncryptedSessionKey.construct_packet(
      pk_algo_identifier,
      k.public_key,
      :aes_256,
      key_bytes,
      <<0::unsigned-big-integer-size(64)>>)
    {:ok, f} = :file.open(packet, [:ram, :binary])
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
