defmodule Pgpex.Armor.Reader do

  @base_64_alphabet [
    "A","B","C","D","E","F","G","H",
    "I","J","K","L","M","N","O","P",
    "Q","R","S","T","U","V","W","X",
    "Y", "Z",
    "a","b","c","d","e","f","g","h",
    "i","j","k","l","m","n","o","p",
    "q","r","s","t","u","v","w","x",
    "y", "z",
    "0", "1", "2", "3", "4", "5",
    "6", "7", "8", "9",
    "+", "/", "=", ".", "_", ",",
    ":", "~"
   ]

  @spec initialize(pid()) :: [any()] | {:error, atom() | {:no_translation, :unicode, :latin1}}
  def initialize(f) do
    with ({:ok, {begins, ends}} <- locate_delimiters(f)) do
      Enum.map(map_header_results(f, begins, ends), fn(hr) ->
        block_label_and_locations = find_block_data_locations(f, hr)
        find_line_breaks_and_create_reader(f, block_label_and_locations)
      end)
    end
  end

  defp find_line_breaks_and_create_reader(f, {lbl, b_pos, e_pos, crc24}) do
    with ({:ok, b64_reader} <- Pgpex.Armor.B64StreamReader.initialize(f, b_pos, e_pos)) do
      {:ok, {lbl, crc24, b64_reader}}
    end
  end

  defp find_line_breaks_and_create_reader(_, a) do
    a
  end

  defp find_block_data_locations(f, [{:begin, lbl, off1},{:end,_,off2}]) do
    with {:ok, start_p} <- :file.position(f, off1),
         {:ok, b_pos} <- read_until_blank_line_followed_by_data(f, start_p, :in_non_empty_line),
         {:ok, e_pos, crc24} <- read_back_until_data_and_crc(f, off2, :no_crc_yet, <<>>) do
      {lbl, b_pos, e_pos, crc24}
    end
  end

  defp read_back_until_data_and_crc(f, pos, :no_crc_yet, crc) do
    with ({:ok, _} <- :file.position(f, pos)) do
      case IO.binread(f, 1) do
        <<d::binary>> ->
          case Enum.member?(@base_64_alphabet, d) do
            false -> read_back_until_data_and_crc(f, pos - 1, :no_crc_yet, crc)
            _ -> read_back_until_data_and_crc(f, pos - 1, :in_crc, d <> crc)
          end
        :eof -> {:error, :eof}
        a -> a
      end
    end
  end

  defp read_back_until_data_and_crc(f, pos, :in_crc, crc) do
    with ({:ok, _} <- :file.position(f, pos)) do
      case IO.binread(f, 1) do
        "=" -> read_back_until_data_and_crc(f, pos - 1, :crc_complete, crc)
        <<d::binary>> ->
          case Enum.member?(@base_64_alphabet, d) do
            false -> read_back_until_data_and_crc(f, pos - 1, :in_crc, crc)
            _ -> read_back_until_data_and_crc(f, pos - 1, :in_crc, d <> crc)
          end
        :eof -> {:error, :eof}
        a -> a
      end
    end
  end

  defp read_back_until_data_and_crc(f, pos, :crc_complete, crc) do
    with ({:ok, _} <- :file.position(f, pos)) do
      case IO.binread(f, 1) do
        <<d::binary>> ->
          case Enum.member?(@base_64_alphabet, d) do
            false -> read_back_until_data_and_crc(f, pos - 1, :crc_complete, crc)
            _ -> {:ok, pos, crc}
          end
        :eof -> {:error, :eof}
        a -> a
      end
    end
  end

  defp read_until_blank_line_followed_by_data(f, pos, :in_new_line) do
    case IO.binread(f, 1) do
      "\r" -> read_until_blank_line_followed_by_data(f,pos + 1, :finished_empty_line)
      "\n" -> read_until_blank_line_followed_by_data(f,pos + 1, :finished_empty_line)
      <<_::binary>> -> read_until_blank_line_followed_by_data(f,pos + 1, :in_non_empty_line)
      :eof -> {:error, :eof}
      a -> a
    end
  end

  defp read_until_blank_line_followed_by_data(f, pos, :finished_empty_line) do
    case IO.binread(f, 1) do
      <<d::binary>> ->
        case Enum.member?(@base_64_alphabet, d) do
          false -> read_until_blank_line_followed_by_data(f, pos + 1, :finished_empty_line)
          _ -> {:ok, pos}
        end
      :eof -> {:error, :eof}
      a -> a
    end
  end

  defp read_until_blank_line_followed_by_data(f, pos, :in_non_empty_line) do
    case IO.binread(f, 1) do
      "\n" -> read_until_blank_line_followed_by_data(f,pos + 1, :in_new_line)
      <<_::binary>> -> read_until_blank_line_followed_by_data(f,pos + 1, :in_non_empty_line)
      :eof -> {:error, :eof}
      a -> a
    end
  end

  defp map_header_results(f, begins, ends) do
    end_info = Enum.map(ends, fn(e) ->
      read_tag_label(f, e, :end, 8)
    end)

    begin_info = Enum.map(begins, fn(b) ->
      read_tag_label(f, b, :begin, 11)
    end)
    {begin_info, end_info}

    entry_set = Enum.sort(begin_info ++ end_info, fn({_,_,off1}, {_,_,off2}) ->
      off1 <= off2
    end)
    Enum.chunk_every(entry_set, 2)
  end

  def read_tag_label(f, loc, tag_label, offset) do
    {:ok, _} = :file.position(f, loc + offset)
    case IO.binread(f, 100) do
      <<data::binary>> ->
        [label|_] = :binary.split(data, "-")
        {tag_label, label, loc}
      a -> a
    end
  end

  defp locate_delimiters(f) do
    case initialize_buffer(f) do
      {:first_part, first_data} -> find_headers(f, first_data, [], [], 0)
      {:all_data, all_data} -> {:ok, search_with_offset_and_unique(all_data, [], [], 0)}
      a -> a
    end
  end

  defp search_with_offset_and_unique(buff, existing_begins, existing_ends, offset) do
    begins = :binary.matches(buff, "-----BEGIN")
    ends = :binary.matches(buff, "-----END")
    begin_offsets = Enum.map(begins, fn({s,_}) ->
      s + offset
    end)
    end_offsets = Enum.map(ends, fn({s,_}) ->
      s + offset + 1
    end)
    {Enum.uniq(existing_begins ++ begin_offsets), Enum.uniq(existing_ends ++ end_offsets)}
  end

  def find_headers(f, <<_::binary-size(4096), second_data::binary-size(4096)>> = buff, existing_begins, existing_ends, offset) do
    {begins, ends} = search_with_offset_and_unique(buff, existing_begins, existing_ends, offset)
    case IO.binread(f, 4096) do
      <<more_data::binary-size(4096)>> -> find_headers(f, second_data <> more_data, begins, ends, offset + 4096)
      <<all_data::binary>> -> {:ok, search_with_offset_and_unique(second_data <> all_data, begins, ends, offset + 4096)}
      :eof -> {:ok, {Enum.uniq(begins), Enum.uniq(ends)}}
      {:error, e} -> {:error, e}
    end
  end

  def initialize_buffer(f) do
    :file.position(f, :bof)
    case IO.binread(f, 8192) do
      <<first_data::binary-size(8192)>> -> {:first_part, first_data}
      <<all_data::binary>> -> {:all_data, all_data}
      {:error, err} -> {:error, err}
      :eof -> {:error, :eof}
    end
  end

end
