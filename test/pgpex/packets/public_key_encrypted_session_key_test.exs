defmodule Pgpex.Packets.PublicKeyEncryptedSessionKeyTest do
  use ExUnit.Case
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

      parsed = Enum.map(result, fn(h) ->
        Pgpex.PacketReader.parse_packet(c, h)
      end)
    end)
    [first_message|_] = parsed_files
    [{:public_key_encrypted_session_key, version, key_id, {:rsa, :both}, packet_data}|_] = first_message
    priv_key = read_rsa_priv_key()
    decrypted_session_key = :public_key.decrypt_private(packet_data, priv_key, [{:rsa_padding, :rsa_no_padding}])
    IO.inspect(Pgpex.Primitives.SessionKey.decode_session_key(decrypted_session_key))
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
        Pgpex.PacketReader.parse_packet(c, h)
      end)
    end)

    priv_key = Enum.at(all_entries, 1)
    rsa_priv_packet = Enum.at(priv_key, 3)

    {:secret_subkey, 4, <<92, 121, 129, 46>>, :rsa, :both, rsa_priv_key} = rsa_priv_packet
    rsa_priv_key
  end
end