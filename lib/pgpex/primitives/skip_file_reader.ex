defmodule Pgpex.Primatives.SkipFileReader do
  defstruct [io: nil, position: 0, length: 0, positions: []]

  @type t :: %__MODULE__{
    position: non_neg_integer(),
    length: non_neg_integer()
  }
  @type position :: {non_neg_integer(), non_neg_integer()}

  @spec new(any(), non_neg_integer(), [position()]) :: Pgpex.Primatives.SkipFileReader.t()
  def new(f, size, positions) do
    %__MODULE__{
      length: size,
      io: f,
      positions: map_indexes(positions)
    }
  end

  def wrap_as_file(stream) do
    spawn(fn() -> loop(stream) end)
  end

  defp loop(skr) do
    receive do
      {:io_request, from, reply_ref, {:get_chars, :"", n}} ->
        handle_read_request(from, reply_ref, skr, n)
      {:file_request, from, reply_ref, {:position, p}} ->
        handle_position_request(from, reply_ref, skr, p)
      {:file_request, from, reply_ref, :close} ->
        send(from, {:file_reply,reply_ref, File.close(skr.io)})
      a ->
        IO.inspect(a)
        loop(skr)
    end
  end

  defp handle_read_request(from, reply_ref, stream, n) do
    case binread(stream, n) do
      {:ok, new_s, data} ->
          send(from, {:io_reply,reply_ref, data})
          loop(new_s)
      :eof ->
        send(from, {:io_reply, reply_ref, :eof})
        loop(stream)
      a ->
        send(from, {:io_reply, reply_ref, {:error, a}})
        loop(stream)
    end
  end

  defp handle_position_request(from, reply_ref, stream, p) do
    case position(stream, p) do
      {:ok, new_s, new_p} ->
          send(from, {:file_reply,reply_ref, {:ok, new_p}})
          loop(new_s)
      a ->
        send(from, {:file_reply, reply_ref, {:error, a}})
        loop(stream)
    end
  end

  def binread(%__MODULE__{length: l, position: pos},_) when pos >= l and pos >= 0 do
    :eof
  end

  def binread(%__MODULE__{io: f, length: l, position: pos, positions: p} = sfr, len) when len >= 0 do
    max_read_pos = case ((pos + len) > l) do
      false -> pos + len - 1
      _ -> l - 1
    end
    readables = map_reading_indexes(pos, max_read_pos, p)
    read_data = Enum.reduce(readables, <<>>, fn({start_pos,read_amount}, data) ->
      :file.position(f, start_pos)
      data <> IO.binread(f, read_amount)
    end)
    {:ok, %__MODULE__{sfr| position: (max_read_pos + 1)}, read_data}
  end

  def position(%__MODULE__{length: l}, pos) when pos > l and pos >= 0 do
    {:error, :einval}
  end

  def position(%__MODULE__{} = sfr, pos) when pos >= 0 do
    {:ok, %__MODULE__{sfr | position: pos}, pos}
  end

  defp map_reading_indexes(read_start, read_end, positions) do
    start_entry_index = Enum.find_index(positions, fn({s, e, _, _}) ->
      (s <= read_start) && (e >= read_start)
    end)
    end_entry_index = Enum.find_index(positions, fn({s, e, _, _}) ->
      (s <= read_end) && (e >= read_end)
    end)
    position_entries = Enum.slice(positions, start_entry_index..end_entry_index)
    Enum.map(position_entries, fn(pos) ->
      map_single_index_for(pos, read_start, read_end)
    end)
  end

  defp map_single_index_for(pos_entry, read_s, read_e) do
    start_idx = pick_start_pos(pos_entry, read_s)
    end_idx = pick_end_pos(pos_entry, read_e)
    {start_idx, end_idx - start_idx + 1}
  end

  defp pick_start_pos({off_s, off_e, f_s, f_e}, read_s) do
    case (read_s <= off_s) do
      true -> f_s
      _ -> (read_s - off_s) + f_s
    end
  end

  defp pick_end_pos({off_s, off_e, f_s, f_e}, read_e) do
    case (read_e >= off_e) do
      true -> f_e
      _ -> f_e - (off_e - read_e)
    end
  end

  def map_indexes(positions) do
    poses = List.keysort(positions, 0)
    {pos_entries, _} = Enum.reduce(poses, {[], 0}, fn({s,e},{col,off}) ->
         part_len = (e - s) + 1
         {[{off, part_len + off - 1, s, e}|col], off + part_len}
       end)
    Enum.reverse(pos_entries)
  end
end
