defmodule Pgpex.Armor.ReaderTest do
  use ExUnit.Case
  doctest Pgpex.Armor.Reader

  test "reading a collection of both public and private keys" do
    f_name = "test/test_data/pub_and_private_key.asc"
    {:ok, f} = :file.open(f_name, [:read, :binary])

    entries = Enum.map(Pgpex.Armor.Reader.initialize(f), fn({:ok, {_a,b,c}}) ->
      {:ok, _} = Pgpex.Armor.B64StreamReader.verify_crc24(c, b)
      {:ok, new_reader} = Pgpex.Armor.B64StreamReader.reopen_as_new_file(c, f_name)
      new_reader
    end)
    :file.close(f)
    Enum.map(entries, fn(c) ->
      :file.position(c, :bof)
      {:ok, result} = Pgpex.PacketReader.read_headers(c)

      Enum.map(result, fn(h) ->
        Pgpex.Packet.parse_packet(c, h)
      end)
    end)
  end

  test "public/private key set rsa encrypt/decrypt" do
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
    priv_key = Enum.at(all_entries, 1)
    rsa_pub_packet = Enum.at(pub_key, 0)
    rsa_priv_packet = Enum.at(priv_key, 0)

    %Pgpex.Packets.PublicKey{tag: :public_key, version: 4, key_time: <<92, 121, 129, 46>>, algo_type: :rsa, usage: :both, public_key: rsa_pub_key} = rsa_pub_packet
    %Pgpex.Packets.SecretKey{tag: :secret_key, version: 4, key_time: <<92, 121, 129, 46>>, algo_type: :rsa, usage: :both, secret_key: rsa_priv_key} = rsa_priv_packet
    test_text = "FRANK"
    ct = :public_key.encrypt_public(test_text,rsa_pub_key)
    ^test_text = :public_key.decrypt_private(ct, rsa_priv_key)
  end
end
