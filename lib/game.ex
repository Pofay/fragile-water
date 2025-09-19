defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  @smsg_auth_challenge 0x1EC

  @impl ThousandIsland.Handler
  def handle_connection(socket, _state) do
    seed = :crypto.strong_rand_bytes(4)
    size = <<6::big-size(16)>>
    opcode = <<@smsg_auth_challenge::little-size(16)>>

    packet =
      size <>
        opcode <>
        seed

    Logger.info("[GameServer] Sending SMSG_AUTH_CHALLENGE with seed: #{inspect(seed)}")

    ThousandIsland.Socket.send(socket, packet)
    {:continue, %{seed: seed}}
  end

  @impl ThousandIsland.Handler
  def handle_data(
        <<size::big-size(16), 0x1ED::little-size(32), body::binary-size(size - 4)>>,
        socket,
        state
      ) do
    <<build::little-size(32), server_id::little-size(32), rest::binary>> = body

    {username, additional_bits} = extract_username_with_rest(rest)

    # <<client_seed :: little-size>>
  end

  def extract_username_with_rest(payload) do
    case :binary.match(payload, <<0>>) do
      {idx, _len} ->
        username = :binary.part(payload, 0, idx)
        rest = :binary.part(payload, idx + 1, byte_size(payload) - (idx + 1))
        {username, rest}

      :nomatch ->
        {payload, <<>>}
    end
  end
end
