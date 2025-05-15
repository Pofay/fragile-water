defmodule FragileWater.Auth do
  @moduledoc """
  Based on implementation from pikdum/thistle_tea
  https://github.com/pikdum/thistle_tea/commit/33a9756eeafc5d24bd903ab9f80b446e72cce428#diff-04ab6d976a6cff089eb06be2022d35e31e31e37e45c3e97f7816ee37521c70cf
  """
  use ThousandIsland.Handler

  @cmd_auth_logon_challenge 0
  @cmd_auth_logon_proof 1

  @n <<137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191,
       191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183>>
  @g <<7>>

  @username "pofay"
  @password "pofay"

  @impl ThousandIsland.Handler
  def handle_data(<<@cmd_auth_logon_challenge, data::binary>>, socket, state) do
    IO.inspect("CMD_AUTH_LOGON_CHALLENGE")

    <<
      size::binary-size(4),
      _rest::binary
    >> = data

    IO.inspect(size, base: :binary)

    ThousandIsland.Socket.send(socket, <<0>>)
    {:continue, state}
  end

  @impl ThousandIsland.Handler
  def handle_data(data, socket, state) do
    IO.inspect("UNHANDLED")
    <<msg::binary-size(1), _rest::binary>> = data
    IO.inspect("Actual Message: #{msg}", base: :binary)
    IO.inspect("Actual Data: #{data}", base: :binary)
    ThousandIsland.Socket.send(socket, data)
    {:continue, state}
  end
end
