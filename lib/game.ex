defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  @impl ThousandIsland.Handler
  def handle_connection(socket, _state) do
    seed = :crypto.strong_rand_bytes(4)
    size = <<6::big-size(16)>>
    opcode = <<0x1EC::little-size(16)>>

    packet =
      size <>
        opcode <>
        seed

    Logger.info("[GameServer] Sending SMSG_AUTH_CHALLENGE with seed: #{inspect(seed)}")

    ThousandIsland.Socket.send(socket, packet)
    {:continue, %{seed: seed}}
  end

  # @impl ThousandIsland.Handler
  # def handle_data(<<size::big-size(16), 0x1ED::little-size(32)>>)
end
