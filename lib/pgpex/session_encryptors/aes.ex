defmodule Pgpex.SessionEncryptors.Aes do
  use Bitwise

  def generate_iv_for(key) do
    iv_bytes = :crypto.strong_rand_bytes(16)
    case iv_bytes do
      ^key -> generate_iv_for(key)
      _ -> iv_bytes
    end
  end

  def init_for(key) do
    hs = :crypto.hash_init(:sha)
    iv = generate_iv_for(key)
    data_prefix = :binary.part(iv, byte_size(iv) - 2, 2)
    h_update = :crypto.hash_update(hs, iv <> data_prefix)
    first_block = encrypt_block(<<0::big-integer-unsigned-size(128)>>, key, iv)
    {
      first_block,
      data_prefix,
      h_update,
      &encrypt_for_buffer/4,
      &finalize_encryption/4
    }
  end

  def encrypt_for_buffer(buffer, new_data, iv, key) do
    new_bin = buffer <> new_data
    chomp_me(new_bin, iv, key, <<>>)
  end

  def finalize_encryption(buffer, hash, iv, key) do
    hash_bytes = :crypto.hash_final(hash)
    {new_iv, remain, to_write} = chomp_me(buffer <> hash_bytes, iv, key, <<>>)
    case remain do
      <<>> -> to_write
      _ -> to_write <> encrypt_block(new_iv, key, remain)
    end
  end

  def encrypt_block(iv, key, plain_text) do
    ct_size = byte_size(plain_text)
    <<ctext_int::big-unsigned-integer-size(128)>> = plain_text <> :binary.copy(<<0>>, 16 - ct_size)
    <<before_ct_apply_int::big-unsigned-integer-size(128)>> = :crypto.block_encrypt(:aes_ecb, key, iv)
    xored = Bitwise.bxor(before_ct_apply_int, ctext_int)
    :binary.part(<<xored::big-unsigned-integer-size(128)>>, 0, ct_size)
  end

  defp chomp_me(<<eatable::binary-size(16), rest::binary>>, iv, key, result) do
    writable_block = encrypt_block(iv, key, eatable)
    chomp_me(rest, writable_block, key, result <> writable_block)
  end

  defp chomp_me(<<left::binary>>, iv, _, result) do
    {iv, left, result}
  end
end
