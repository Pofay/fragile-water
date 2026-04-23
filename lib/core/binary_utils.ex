defmodule FragileWater.Core.BinaryUtils do
  def extract_name_with_rest(payload) do
    case :binary.match(payload, <<0>>) do
      {idx, _len} ->
        name = :binary.part(payload, 0, idx)
        rest = :binary.part(payload, idx + 1, byte_size(payload) - (idx + 1))
        {name, rest}

      :nomatch ->
        {payload, <<>>}
    end
  end
end
