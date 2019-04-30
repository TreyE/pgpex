defmodule Pgpex.Primitives.S2K.RSASecretKey do

  defstruct [
    m: nil,
    e: nil,
    hash_algo: :sha1,
    hash_salt: nil,
    iterations: nil,
    sym_algo: :aes_128,
    initialization_vector: nil,
    check_algo: :sha1,
    specifier: :iterated_and_salted,
    encrypted_packet_bytes: nil
  ]

  import Pgpex.Primitives.IOUtils
  use Bitwise

  def new(m, e, c_algo \\ :sha1) do
    %__MODULE__{
      m: m,
      e: e,
      check_algo: c_algo
    }
  end

  def read_rsa_s2k(f) do
    binread_match(f, 1, :read_secret_key_s2k_eof, :unsupported_secret_key_s2k) do
      <<0::big-unsigned-integer-size(8)>> -> {:ok, :unencrypted}
      <<254::big-unsigned-integer-size(8)>> -> {:ok, :s2k_specifier_sha1}
      <<255::big-unsigned-integer-size(8)>> -> {:ok, :s2k_specifier_csum}
      <<a::big-unsigned-integer-size(8)>> -> {:ok, {:s2k_direct_algo, a}}
    end
  end

  def read_s2k_algo(mod, f) do
    binread_match(f, 1, :read_secret_key_s2k_algo_eof, :unsupported_secret_key_s2k_algo) do
      <<0x07::big-unsigned-integer-size(8)>> -> {:ok, %__MODULE__{mod | sym_algo: :aes_128}}
    end
  end

  def read_s2k_specifier(m, f) do
    binread_match(f, 1, :read_secret_key_s2k_specifier_eof, :unsupported_secret_key_s2k_specifier) do
      <<0x00::big-unsigned-integer-size(8)>> -> {:ok, %__MODULE__{m | specifier: :simple}}
      <<0x01::big-unsigned-integer-size(8)>> -> {:ok, %__MODULE__{m | specifier: :salted}}
      <<0x03::big-unsigned-integer-size(8)>> -> {:ok, %__MODULE__{m | specifier: :iterated_and_salted}}
    end
  end

  def process_s2k_parts(%__MODULE__{specifier: :iterated_and_salted, sym_algo: :aes_128} = mod, f, l_left) do
    with {:ok, c_pos} <- :file.position(f, :cur),
         {:ok, m_with_h_algo} <- read_s2k_hash_algo(mod, f),
         {:ok, m_with_h_salt} <- read_s2k_salt(m_with_h_algo, f),
         {:ok, m_with_h_iterations} <- read_s2k_count(m_with_h_salt, f),
         {:ok, n_pos} <- :file.position(f, :cur) do
      process_s2k_data(
        m_with_h_iterations,
        f,
        l_left - (n_pos - c_pos)
      )
    end
  end

  def process_s2k_parts(mod, _, _) do
    {:error, {:unsupported_secret_key_s2k_specifier, mod}}
  end

  defp process_s2k_data(
    %__MODULE__{
      hash_algo: :sha1,
      sym_algo: :aes_128
    } = mod,
    f,
    l_left) do
    with  {:ok, c_pos} <- :file.position(f, :cur),
          {:ok, m_with_iv} <- read_s2k_iv_16(mod, f),
          {:ok, n_pos} <- :file.position(f, :cur),
          remaining = l_left - (n_pos - c_pos),
          {:ok, finished_mod} <- read_remaining_packet_bytes(m_with_iv, f,remaining) do
      {:ok, finished_mod}
    end
  end

  defp process_s2k_data(mod, _, _) do
    {:error, {:unsupported_secret_key_s2k_algo_pairing, mod}}
  end

  defp read_s2k_hash_algo(mod, f) do
    binread_match(f, 1, :read_secret_key_s2k_hash_algo_eof, :unsupported_secret_key_s2k_hash_algo) do
      <<0x02::big-unsigned-integer-size(8)>> -> {:ok, %__MODULE__{mod | hash_algo: :sha1}}
    end
  end

  defp read_s2k_salt(mod, f) do
    binread_match(f, 8, :read_secret_key_s2k_salt_eof, :unsupported_secret_key_s2k_salt) do
      <<a::binary-size(8)>> -> {:ok, %__MODULE__{mod | hash_salt: a}}
    end
  end

  defp read_s2k_count(mod, f) do
    binread_match(f, 1, :read_secret_key_s2k_iterations_eof, :unsupported_secret_key_s2k_iterations) do
      <<a::big-unsigned-integer-size(8)>> -> {:ok, %__MODULE__{mod | iterations: decode_s2k_iterations(a)}}
    end
  end

  defp decode_s2k_iterations(int_val) do
    first_part = 16 + Bitwise.band(int_val, 15)
    second_part = div(int_val, 16) + 6
    Bitwise.bsl(first_part,second_part)
  end

  defp read_s2k_iv_16(mod, f) do
    binread_match(f, 16, :read_secret_key_s2k_iv_eof, :unsupported_secret_key_s2k_iv) do
      <<a::binary-size(16)>> -> {:ok, %__MODULE__{mod | initialization_vector: a}}
    end
  end

  def read_remaining_packet_bytes(mod, f, size) do
    case IO.binread(f, size) do
      <<data::binary-size(size)>> -> {:ok, %__MODULE__{mod | encrypted_packet_bytes: data}}
      <<not_enough_data::binary>> -> {:error, {:secret_key_s2k_packet_remainder_too_short, not_enough_data}}
      a -> {:error, a}
    end
  end

  defp calculate_session_key(
    %__MODULE__{
      hash_algo: :sha1,
      sym_algo: :aes_128,
      specifier: :iterated_and_salted
    } = m, password) do
    salt = m.hash_salt
    iters = m.iterations
    hash_input = stretch_values(password, salt, <<>>, iters)
    final_h = :crypto.hash(:sha, hash_input)
    :binary.part(final_h, 0, 16)
  end

  defp calculate_session_key(m, _) do
    {:error, {:unsupported_s2k_session_key_calculation_set, m}}
  end

  def unlock_key(
    %__MODULE__{
      hash_algo: :sha1,
      sym_algo: :aes_128,
      specifier: :iterated_and_salted,
      check_algo: :sha1
    } = m, password) do
    s_key = calculate_session_key(m, password)
    iv = m.initialization_vector
    e_bytes = m.encrypted_packet_bytes
    decrypted_bytes = decrypt_aes_block(iv, s_key, e_bytes, <<>>)
    with ({:ok, data_bytes} <- check_private_bytes(:sha1, decrypted_bytes)) do
      read_and_build_key(m, data_bytes)
    end
  end

  def unlock_key(m, _) do
    {:error, {:unsupported_s2k_session_key_calculation_set, m}}
  end

  def check_private_bytes(:sha1, private_bytes) do
    hash_part = :binary.part(private_bytes, byte_size(private_bytes) - 20, 20)
    data_part = :binary.part(private_bytes, 0, byte_size(private_bytes) - 20)
    hash_val = :crypto.hash(:sha, data_part)
    case hash_part do
      ^hash_val -> {:ok, data_part}
      _ -> {:error, {:s2k_checksum_mismatch, hash_part, hash_val}}
    end
  end

  def check_private_bytes(method, _) do
    {:error, {:unsupported_s2k_checksum_method, method}}
  end

  defp decrypt_aes_block(_, _, <<>>, so_far) do
    so_far
  end

  defp decrypt_aes_block(iv, s_key, <<c_text::binary-size(16), rest::binary>>, so_far) do
    decrypted = Pgpex.SessionDecryptors.Aes.decrypt_block(iv, s_key, c_text)
    decrypt_aes_block(c_text, s_key, rest, so_far <> decrypted)
  end

  defp decrypt_aes_block(iv, s_key, c_text, so_far) do
    decrypted = Pgpex.SessionDecryptors.Aes.decrypt_block(iv, s_key, c_text)
    so_far <> decrypted
  end

  defp read_and_build_key(mod, data_bytes) do
    with ({:ok, d, p, q, u} <- read_rsa_components(data_bytes)) do
      create_rsa_private_key_record(mod.m, mod.e, d, p, q, u)
    end
  end

  defp read_rsa_components(data_bytes) do
    with {:ok, d, rem_1} <- Pgpex.Primitives.Mpi.decode_first_mpi_from_bytes(data_bytes),
      {:ok, p, rem_2} <- Pgpex.Primitives.Mpi.decode_first_mpi_from_bytes(rem_1),
      {:ok, q, rem_3} <- Pgpex.Primitives.Mpi.decode_first_mpi_from_bytes(rem_2),
      {:ok, u, _} <- Pgpex.Primitives.Mpi.decode_first_mpi_from_bytes(rem_3) do
       {:ok, d, p, q, u}
    end
  end

  defp create_rsa_private_key_record(m, e, d, p, q, u) do
    {:'RSAPrivateKey', 1, m, e, d, p, q, rem(d, p - 1), rem(d, q - 1), u, :asn1_NOVALUE}
  end

  defp stretch_values(pword, salt, pre_pad, iter) do
    salted_pw = salt <> pword
    salted_pw_size = byte_size(salted_pw)
    copies = div(iter, salted_pw_size)
    remainder = rem(iter, salted_pw_size)
    remainder_bin = case remainder > 0 do
      false -> <<>>
      _ -> pre_pad <> :binary.part(salted_pw, 0, remainder)
    end
    :binary.copy(pre_pad <> salted_pw, copies) <> remainder_bin
  end
end
