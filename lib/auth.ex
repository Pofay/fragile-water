defmodule FragileWater.Auth do
  @moduledoc """
  Based on implementation from pikdum/thistle_tea
  https://github.com/pikdum/thistle_tea/commit/33a9756eeafc5d24bd903ab9f80b446e72cce428#diff-04ab6d976a6cff089eb06be2022d35e31e31e37e45c3e97f7816ee37521c70cf
  """
  use ThousandIsland.Handler
  require Logger

  alias FragileWater.Core.Cmd.AuthLogonChallenge
  alias FragileWater.Core.Cmd.AuthLogonProof
  alias FragileWater.Core.Cmd.RealmList

  alias FragileWater.SessionKeyStorage

  @cmd_auth_logon_challenge 0
  @cmd_auth_logon_proof 1
  @cmd_realm_list 16

  @impl ThousandIsland.Handler
  def handle_data(
        <<@cmd_auth_logon_challenge, _rest::binary>> = packet,
        socket,
        state
      ) do
    {state, packet} = AuthLogonChallenge.generate_payload(packet, state)

    ThousandIsland.Socket.send(
      socket,
      packet
    )

    {:continue, state}
  end

  @impl ThousandIsland.Handler
  # From https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Client
  def handle_data(
        <<@cmd_auth_logon_proof, _rest::binary>> = packet,
        socket,
        state
      ) do
    {state, packet} = AuthLogonProof.generate_payload(packet, state)

    case packet do
      <<0, 0, 5>> ->
        ThousandIsland.Socket.send(socket, packet)
        {:close, state}

      _ ->
        SessionKeyStorage.put(state.account_name, state.session)
        ThousandIsland.Socket.send(socket, packet)
        {:continue, state}
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(<<@cmd_realm_list, _padding::binary>> = packet, socket, state) do
    {state, packet} = RealmList.generate_payload(packet, state)

    ThousandIsland.Socket.send(socket, packet)
    {:continue, state}
  end

  @impl ThousandIsland.Handler
  def handle_data(<<opcode, _packet::binary>>, socket, state) do
    Logger.error("UNHANDLED opcode: #{opcode}")
    ThousandIsland.Socket.send(socket, <<0, 0, 5>>)
    {:close, state}
  end
end
