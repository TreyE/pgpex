defmodule Pgpex.Primitives.Behaviours.ReadableFile do
  @type readable_file_struct :: map()

  @type read_position :: :bof | :eof | :cur | non_neg_integer()

  @callback binread(readable_file_struct(),non_neg_integer()) :: :eof | {:error, any()} | {:ok, readable_file_struct(), binary()}

  @callback position(readable_file_struct(),read_position) :: any()

  @callback close(readable_file_struct()) :: any()

  def wrap_as_file(mod, stream) do
    pid = spawn(fn() -> loop(mod, stream) end)
    case function_exported?(mod, :transfer_ownership, 2) do
      false -> pid
      _ ->
        mod.transfer_ownership(stream, pid)
        pid
    end
  end

  defp loop(mod, skr) do
    receive do
      {:io_request, from, reply_ref, {:get_chars, :"", n}} ->
        handle_read_request(mod, from, reply_ref, skr, n)
      {:file_request, from, reply_ref, {:position, p}} ->
        handle_position_request(mod, from, reply_ref, skr, p)
      {:file_request, from, reply_ref, :close} ->
        send(from, {:file_reply,reply_ref, mod.close(skr.io)})
      a ->
        IO.inspect(a)
        loop(mod, skr)
    end
  end

  defp handle_read_request(mod, from, reply_ref, stream, n) do
    case mod.binread(stream, n) do
      {:ok, new_s, data} ->
          send(from, {:io_reply,reply_ref, data})
          loop(mod, new_s)
      :eof ->
        send(from, {:io_reply, reply_ref, :eof})
        loop(mod, stream)
      a ->
        send(from, {:io_reply, reply_ref, {:error, a}})
        loop(mod, stream)
    end
  end

  defp handle_position_request(mod, from, reply_ref, stream, p) do
    case mod.position(stream, p) do
      {:ok, new_s, new_p} ->
          send(from, {:file_reply,reply_ref, {:ok, new_p}})
          loop(mod, new_s)
      a ->
        send(from, {:file_reply, reply_ref, {:error, a}})
        loop(mod, stream)
    end
  end
end
