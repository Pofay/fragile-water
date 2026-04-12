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

  @handlers [
    AuthLogonChallenge,
    AuthLogonProof,
    RealmList
  ]

  @impl ThousandIsland.Handler
  def handle_data(<<opcode, _packet::binary>> = request, socket, state) do
    handler =
      @handlers
      |> Enum.find(fn handler -> handler.can_handle?(opcode) end)

    case handler do
      nil ->
        Logger.error("UNHANDLED opcode: #{opcode}")
        ThousandIsland.Socket.send(socket, <<0, 0, 5>>)
        {:close, state}

      handler ->
        {action, state, response} = handler.generate_payload(request, state)
        ThousandIsland.Socket.send(socket, response)
        {action, handler.post_handle(state)}
    end
  end
end
