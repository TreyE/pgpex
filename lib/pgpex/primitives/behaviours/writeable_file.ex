defmodule Pgpex.Primitives.Behaviours.WritableFile do
  @type writable_file_struct :: map()

  @callback binwrite(writable_file_struct(),iolist()) :: :eof | {:error, any()} | {:ok, writable_file_struct()}

  def wrap_as_file(mod, stream) do
    pid = spawn(fn() -> loop(mod, stream) end)
    case function_exported?(mod, :transfer_ownership, 2) do
      false -> pid
      _ ->
        mod.transfer_ownership(stream, pid)
        pid
    end
  end

  def unwrap(pid, timeout \\ 15000) do
    send(pid, {:unwrap, self()})
    receive do
      {:ok, skr} -> {:ok, skr}
    after
      timeout -> {:error, {:timeout, pid}}
    end
  end

  defp loop(mod, skr) do
    receive do
      {:unwrap, from} ->
        send(from, {:ok, skr})
      {:io_request, from, reply_ref, {:put_chars, _, chars}} ->
        handle_write_request(mod, from, reply_ref, skr, chars)
      a ->
        IO.inspect(a)
        loop(mod, skr)
    end
  end

  defp handle_write_request(mod, from, reply_ref, stream, chars) do
    case mod.binwrite(stream, chars) do
      {:ok, new_s} ->
          send(from, {:io_reply,reply_ref, :ok})
          loop(mod, new_s)
      a ->
        send(from, {:io_reply, reply_ref, {:error, a}})
        loop(mod, stream)
    end
  end
end
