defmodule Pgpex.PacketReaderTest do
  use ExUnit.Case
  doctest Pgpex.PacketReader

  @source_data_1 "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"

  @source_data_2 "hQIMA+jTPgwZ9PZ0ARAAobxL6y/gI6wBk/NXocuYwY8IrUs3LVpMXrrnHqQ/p/dK
  pQgMuVyWejudtYp+CLMjIjSasvIaNVg+zYt1W5Dn6T60X5hywBeo4GtpVVCoTlaY
  6iuFgR2z+V/dBccCqojLefiJsbj0cBq8nUAOy25nD4CQU5JbuX7exyRMLLancyYP
  OKTqbUHy9tOCm2W9nRMKXiRrYp+nNbpyOkaG0eRJPnotFd/WnA/SvG7gPkjnHwAS
  ibGgJg20AI6reJa2U8i1LygRz0P5qavtx5P6jZut67lmosqoRuxuxnJBYKinThHZ
  iRhv9cgrfFxJ+xvBNBuNWvPMMFqhcwGt7iDV6tRs3KX05n1bzT08tw/GLWn/RkpH
  WuspFTsHsOlaCGYGHfxy9//0u4hk5He9dtSVHrZbYDkhAN9Zjeet0dbNjmfPOsik
  1w8WfvttVEUOt3KOIfvCeSKPy1whqwB/AVvTni5BjQAFfeviYAsQ6JKf1P8z7SwP
  eb3hHp6iOittpl93wcBCY0G9GDht3L5RRTjSsoEgUq5MmiXZcmeMFB9wWXmTrZXq
  qpebrhy5DGbcyJF9RTkFeR+1pMIhkHrFc0dH1DxQ092n5Ag7KSmn7u/ue1mft62V
  BzCwiWw2Qu2G5bFTtyNsOpA5NxFtGFAqmg+LC5xJVyvQgdNA8kkQ70+/CBMOz5LS
  wK4BManaZdgcxOXJpfzh+AtLijjKOKMkNNJvSc1ecU8v++k1oiEy3e7sgNfNkmWB
  4yP977lH3CxnAM90NNZ2HFQOg9bqMf56fux/2WSOgrF7xpDUuA2XXZ28XgCbbHpa
  0Rmv8Q0qkpZSAEq9PZOcdkG8T7st6vcC3gQEdj+ufnQp2qZHE6kB71S/wSsFmNQ5
  D4F8TIgztH7jo2EScvTigjj7EnmlfvmOo7GmFCuvtKd6yeLHRAxhx0gFKv2jcQ7i
  sApqRoJh/Tx9YATxy1CzqRCYpE5dlCc1dY5THDMSVnXiSJZLR7peI8Bm5uIB/Nr6
  y1ZAGOP5yT/YPbpCKhK1yOZ05Dp6I1/froahTOmEBB79g39MbEF31CHAAwnm+Ao0
  T/Z6ymeQPl6OhG+DSE9nH6Up80QcaAjrgkILYEhtvQ8Iq3s54MXrfvyiEsBa7uCo
  hSppoNf12bygIu4FR2I8CGZyl5ZKZUek/OoIEWlZqM8="

  test "reading the first source example" do
    f_name = "my_export_public_key_header_data.gpg"
    {:ok, out_f} = :file.open(f_name, [:binary, :write])
    {:ok, packets_data} = Base.decode64(@source_data_1, ignore: :whitespace, padding: false)
    IO.binwrite(out_f, packets_data)
    :file.close(out_f)

    {:ok, in_f} = :file.open(f_name, [:binary, :read])
    {:ok, parsed} = Pgpex.PacketReader.read_headers(in_f)
    5 = Enum.count(parsed)
    :file.close(in_f)
    File.rm!(f_name)
  end

  test "reading the second source example" do
    f_name = "my_export_encrypted_header_data.gpg"
    {:ok, out_f} = :file.open(f_name, [:binary, :write])
    {:ok, packets_data} = Base.decode64(@source_data_2, ignore: :whitespace, padding: false)
    IO.binwrite(out_f, packets_data)
    :file.close(out_f)

    {:ok, in_f} = :file.open(f_name, [:binary, :read])
    {:ok, result} = Pgpex.PacketReader.read_headers(in_f)
    parsed = Enum.map(result, fn(h) -> Pgpex.Packet.parse_packet(in_f, h) end)
    2 = Enum.count(parsed)
    :file.close(in_f)
    File.rm!(f_name)
  end

  test "given a long encrypted file" do
    f_name = "all_code.asc"
    {:ok, f} = :file.open(f_name, [:binary, :read])
    [{_, _, bsr}|_] = Enum.map(Pgpex.Armor.Reader.initialize(f), fn({:ok, {a,b,c}}) ->
      {:ok, new_reader} = Pgpex.Armor.B64StreamReader.reopen_as_new_file(c, f_name)
      {a, b, new_reader}
    end)
    :file.close(f)
    :file.position(bsr, :bof)
    {:ok, headers} = Pgpex.PacketReader.read_headers(bsr)
    packet_results = Enum.map(headers, fn(h) -> Pgpex.Packet.parse_packet(bsr, h) end)
    [{:public_key_encrypted_session_key, _, _, {:rsa, :both}, packet_data},op] = packet_results
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
    "all_code" = lit_packet.file_name
    {:ok, _, "diff --git a/.formatter.exs b"} = Pgpex.Primatives.SkipFileReader.binread(lit_packet.reader, 29)
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
