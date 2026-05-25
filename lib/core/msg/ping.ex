defmodule FragileWater.Core.Msg.Ping do
  require Logger

  @cmsg_ping 0x1DC
  @smsg_pong 0x1DD

  def handle(@cmsg_ping, body, state) do
    Logger.info("[GameServer] CMSG_PING")

    <<sequence_id::little-size(32), latency::little-size(32)>> = body

    Logger.info("[GameServer] CMSG_PING: sequence_id: #{sequence_id}, latency: #{latency}")

    packet = <<sequence_id::little-size(32)>>
    state = Map.merge(state, %{latency: latency})

    {@smsg_pong, packet, state}
  end
end
