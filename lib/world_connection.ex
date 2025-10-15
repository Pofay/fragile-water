defmodule FragileWater.WorldConnection do
  require Logger
  use Agent

  alias FragileWater.Encryption

  def start_link(initial_crypto_state) do
    Agent.start_link(fn -> initial_crypto_state end, name: __MODULE__)
  end

  def update(pid, new_crypto_state) do
    Agent.update(pid, &internal_update(new_crypto_state, &1))
  end

  def get(pid) do
    Agent.get(pid, fn current_crypto_state -> current_crypto_state end)
  end

  def send_packet_and_update(pid, socket, opcode, payload) do
    Agent.get_and_update(pid, fn state ->
      {packet, new_state} = Encryption.build_packet(opcode, payload, state)
      ThousandIsland.Socket.send(socket, packet)
      Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")
      {state, new_state}
    end)
  end

  defp internal_update(new_crypto_state, current_crypto_state) do
    %{
      current_crypto_state
      | send_i: new_crypto_state.send_i,
        send_j: new_crypto_state.send_j,
        recv_i: new_crypto_state.recv_i,
        recv_j: new_crypto_state.recv_j
    }
  end
end
