defmodule Pgpex.Packets.SecretKeyTest do
  use ExUnit.Case
  use Bitwise
  doctest Pgpex.Packets.SecretKey

  test "unlocks the secret key when it is password locked with aes 128" do
      f_name = "test/test_data/secret_key_with_password.asc"
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
      secret_subkey_encrypted = Enum.at(Enum.at(all_entries, 0), 3)
      {:error, {:s2k_checksum_mismatch, _, _}} = Pgpex.Primitives.S2K.RSASecretKey.unlock_key(secret_subkey_encrypted.secret_key, "SOMEBADPASSWORD")
      unlocked_key = Pgpex.Primitives.S2K.RSASecretKey.unlock_key(secret_subkey_encrypted.secret_key, "SOMEPASSWORD")
      ^unlocked_key = read_rsa_priv_key()
  end

  test "unlocks the secret key when it is password locked with aes 256" do
    f_name = "test/test_data/secret_key_with_password_aes_256.asc"
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
    secret_subkey_encrypted = Enum.at(Enum.at(all_entries, 0), 3)
    {:error, {:s2k_checksum_mismatch, _, _}} = Pgpex.Primitives.S2K.RSASecretKey.unlock_key(secret_subkey_encrypted.secret_key, "SOMEBADPASSWORD")
    unlocked_key = Pgpex.Primitives.S2K.RSASecretKey.unlock_key(secret_subkey_encrypted.secret_key, "SOMEPASSWORD")
    correct_key = read_rsa_priv_key()
    ^correct_key = unlocked_key
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
