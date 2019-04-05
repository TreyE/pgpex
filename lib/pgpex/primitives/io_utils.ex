defmodule Pgpex.Primitives.IOUtils do
  defmacro binread_match(f, size, eof_error, invalid_error, do: s_block) do
    clauses = quote do
      <<invalid_data::binary>> -> {:error, {unquote(invalid_error), invalid_data}}
      :eof -> {:error, unquote(eof_error)}
      a -> {:error, a}
    end
    quote do
      case IO.binread(unquote(f),unquote(size)) do unquote(s_block ++ clauses) end
    end
  end

  defmacro seek_or_error(f, pos, error_name) do
    quote do
      case :file.position(unquote(f), unquote(pos)) do
        {:ok, pos} -> :ok
        {:error, a} -> {:error, {unquote(error_name), a}}
      end
    end
  end
end
