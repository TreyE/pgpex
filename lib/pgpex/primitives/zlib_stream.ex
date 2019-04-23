defmodule Pgpex.Primitives.ZlibStream do
  defstruct [
    skip_file_reader: nil,
    length: 0,
    position: 0,
    buffer: <<>>,
    buffer_start: 0,
    buffer_length: 0,
    z_instance: nil,
    z_has_more: false
  ]

  @behaviour Pgpex.Primitives.Behaviours.ReadableFile

  defp buffer_has(buffer_start, buffer_length, pos) do
    case (pos < buffer_start) do
      false -> (pos <= (buffer_start + buffer_length - 1))
      _ -> false
    end
  end

  def transfer_ownership(%__MODULE__{} = zl, pid) do
    :zlib.set_controlling_process(zl.z_instance, pid)
  end

  def wrap_as_file(stream) do
    Pgpex.Primitives.Behaviours.ReadableFile.wrap_as_file(__MODULE__, stream)
  end

  def close(%__MODULE__{} = zl)  do
    :zlib.inflateEnd(zl.z_instance)
    :zlib.close(zl.z_instance)
  end

  def position(%__MODULE__{position: pos} = zl, :cur) do
    {:ok, zl, pos}
  end

  def position(%__MODULE__{} = zl, :bof) do
    moved_zl = pull_to_start(zl, 0)
    {:ok, %__MODULE__{moved_zl | position: 0}, 0}
  end

  def position(%__MODULE__{length: l} = zl, pos) when (pos <= l) do
    {:ok, %__MODULE__{zl | position: pos}, pos}
  end

  def position(%__MODULE__{length: l}, pos) when (pos > l) do
    {:error, :ebadarg}
  end

  def binread(%__MODULE__{position: pos, length: l}, _) when (pos >= l) and pos >= 0 do
    :eof
  end

  def binread(%__MODULE__{position: pos, length: l} = zl, read_length) when (pos >= 0) do
    suggested_end_offset = pos + read_length - 1
    end_index = case (suggested_end_offset >= l) do
                  false -> suggested_end_offset
                  _ -> l - 1
                end
    z_ended = pull_to_range(zl, pos, end_index)
    read_data = extract_range(z_ended, pos, end_index)
    {:ok, %__MODULE__{z_ended | position: (end_index + 1)}, read_data}
  end

  defp pull_to_start(%__MODULE__{} = zl, start_pos) do
    re_initialized_zl = case (start_pos < zl.buffer_start) do
      false -> zl
      _ -> reopen_zl(zl)
    end
    pull_until_started(re_initialized_zl, start_pos)
  end

  defp pull_to_range(%__MODULE__{} = zl, start_pos, end_pos) do
    z_started = pull_to_start(zl, start_pos)
    pull_until_ended(z_started, end_pos)
  end

  defp extract_range(%__MODULE__{} = zl, start_pos, end_pos) do
    offset_from_start = start_pos - zl.buffer_start
    difference_from_end = ((zl.buffer_start + zl.buffer_length - 1) - end_pos)
    :binary.part(zl.buffer, offset_from_start, zl.buffer_length - offset_from_start - difference_from_end)
  end

  def reopen_zl(%__MODULE__{} = zl) do
    :zlib.inflateEnd(zl.z_instance)
    :zlib.close(zl.z_instance)
    z_i = :zlib.open()
    :zlib.inflateInit(z_i)
    {:ok, new_skr, _} = Pgpex.Primitives.SkipFileReader.position(zl.skip_file_reader, 0)
    %__MODULE__{zl |
    z_instance: z_i,
    position: 0,
    buffer: <<>>,
    buffer_length: 0,
    skip_file_reader: new_skr
  }
  end

  defp pull_until_started(%__MODULE__{buffer_start: bs, buffer_length: bl} = zl, pos) when (pos >= bs) and (pos <= (bs + bl - 1)) do
    zl
  end

  defp pull_until_started(%__MODULE__{} = zl, pos) do
    {new_skr, z, new_buff, buffer_start, buffer_length, b_more} =  pull_buffer(
      zl.skip_file_reader,
      zl.z_instance,
      zl.buffer,
      zl.buffer_start,
      zl.buffer_length,
      zl.z_has_more
    )
    case buffer_has(buffer_start, buffer_length, pos) do
      false ->
        pull_until_started(
          %__MODULE__{
            zl |
            skip_file_reader: new_skr,
            buffer: <<>>,
            buffer_start: buffer_start + buffer_length,
            buffer_length: 0,
            z_has_more: b_more
          },
          pos
        )
      _ ->
        %__MODULE__{
          zl |
            skip_file_reader: new_skr,
            buffer: new_buff,
            buffer_start: buffer_start,
            buffer_length: buffer_length,
            z_has_more: b_more
        }
    end
  end

  defp pull_until_ended(%__MODULE__{buffer_start: bs, buffer_length: bl} = zl, pos) when (pos >= bs) and (pos <= (bs + bl - 1)) do
    zl
  end

  defp pull_until_ended(%__MODULE__{} = zl, pos) do
    {new_skr, z, new_buff, buffer_start, buffer_length, b_more} =  pull_buffer(
      zl.skip_file_reader,
      zl.z_instance,
      zl.buffer,
      zl.buffer_start,
      zl.buffer_length,
      zl.z_has_more
    )
    case buffer_has(buffer_start, buffer_length, pos) do
      false ->
        pull_until_ended(
          %__MODULE__{
            zl |
            skip_file_reader: new_skr,
            buffer: new_buff,
            buffer_start: buffer_start,
            buffer_length: buffer_length,
            z_has_more: b_more
          },
          pos
        )
      _ ->
        %__MODULE__{
          zl |
            skip_file_reader: new_skr,
            buffer: new_buff,
            buffer_start: buffer_start,
            buffer_length: buffer_length,
            z_has_more: b_more
        }
    end
  end

  defp pull_buffer(skr, z, current_buffer, buffer_start, buffer_length, true) do
    case :zlib.safeInflate(z, []) do
      {:continue, [<<>>]} ->
        pull_buffer(skr, z, current_buffer, buffer_start, buffer_length, true)
      {:continue, [c_output]} ->
        {skr, z, current_buffer <> c_output, buffer_start, buffer_length + byte_size(c_output), true}
      {:finished, [output]} ->
        {skr, z, current_buffer <> output, buffer_start, buffer_length + byte_size(output), false}
      {:finished, []} ->
        pull_buffer(skr, z, current_buffer, buffer_start, buffer_length, false)
    end
  end

  defp pull_buffer(skr, z, current_buffer, buffer_start, buffer_length, false) do
    case Pgpex.Primitives.SkipFileReader.binread(skr, 4096) do
      {:ok, new_skr, <<data::binary>>} ->
        case :zlib.safeInflate(z, data) do
          {:continue, [<<>>]} ->
            pull_buffer(new_skr, z, current_buffer, buffer_start, buffer_length, true)
          {:continue, [c_output]} ->
            {new_skr, z, current_buffer <> c_output, buffer_start, buffer_length + byte_size(c_output), true}
          {:finished, [output]} ->
            {new_skr, z, current_buffer <> output, buffer_start, buffer_length + byte_size(output), false}
          {:finished, []} ->
            pull_buffer(new_skr, z, current_buffer, buffer_start, buffer_length, false)
        end
      :eof -> {skr, z, current_buffer, buffer_start, buffer_length}
      a -> {:error, a}
    end
  end

  defp read_length(reader) do
    :ok = :zlib.inflateInit(reader.z_instance)
    stream = Stream.unfold({:run_z, reader.z_instance, reader.skip_file_reader, <<>>, false}, fn(acc) ->
      zlib_unfold_loop(acc)
    end)
    total_length = Enum.reduce(stream, 0, fn(e, acc) ->
      acc + byte_size(e)
    end)
    new_zl = reopen_zl(reader)
    %__MODULE__{new_zl | length: total_length}
  end

  def create_reader_stream(skr) do
    z_i = :zlib.open()
    new_zl = %__MODULE__{skip_file_reader: skr, z_instance: z_i}
    {:ok, read_length(new_zl)}
  end

  defp zlib_unfold_loop({:run_z, z, skr, current_data, true}) do
    case :zlib.safeInflate(z, []) do
      {:continue, []} -> zlib_unfold_loop({:run_z, z, skr, current_data, true})
      {:continue, [c_output]} -> {current_data <> c_output, {:run_z, z, skr, <<>>, true}}
      {:finished, [output]} -> {current_data <> output, {:run_z, z, skr, <<>>, false}}
      {:finished, []} -> zlib_unfold_loop({:run_z, z, skr, current_data, false})
    end
  end

  defp zlib_unfold_loop({:run_z, z, skr, current_data, false}) do
    case Pgpex.Primitives.SkipFileReader.binread(skr, 4096) do
      {:ok, new_skr, <<data::binary>>} ->
        case :zlib.safeInflate(z, data) do
          {:continue, []} -> zlib_unfold_loop({:run_z, z, new_skr, current_data, true})
          {:continue, [c_output]} -> {current_data <> c_output, {:run_z, z, new_skr, <<>>, true}}
          {:finished, [output]} -> {current_data <> output, {:run_z, z, new_skr, <<>>, false}}
          {:finished, []} -> zlib_unfold_loop({:run_z, z, new_skr, current_data, false})
        end
      :eof ->
        {current_data, :stop}
      a ->
        nil
    end
  end

  defp zlib_unfold_loop(:stop) do
    nil
  end
end
