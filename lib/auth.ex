defmodule FragileWater.Auth do
  @moduledoc """
  Based on implementation from pikdum/thistle_tea
  https://github.com/pikdum/thistle_tea/commit/33a9756eeafc5d24bd903ab9f80b446e72cce428#diff-04ab6d976a6cff089eb06be2022d35e31e31e37e45c3e97f7816ee37521c70cf
  """
  use ThousandIsland.Handler
  require Logger

  import Binary, only: [reverse: 1]

  @cmd_auth_logon_challenge 0
  @cmd_auth_logon_proof 1

  @n <<137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191,
       191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183>>
  @g <<7>>

  @username "pofay"
  @password "pofay"

  @impl ThousandIsland.Handler
  def handle_data(
        <<@cmd_auth_logon_challenge, _error::little-size(8), _size::little-size(16),
          _game::bytes-little-size(4), _v1::little-size(8), _v2::little-size(8),
          _v3::little-size(8), _build::little-size(16), _platform::bytes-little-size(4),
          _os::bytes-size(4), _locale::bytes-size(4), _utc_offset::little-size(32),
          _ip::little-size(32), username_length::unsigned-little-size(8),
          username::bytes-little-size(username_length)>>,
        socket,
        _state
      ) do
    Logger.info("Handling logon challenge")
    salt = :crypto.strong_rand_bytes(32)
    hash = :crypto.hash(:sha, String.upcase(@username) <> ":" <> String.upcase(@password))
    # Based on Shadowburn's implementation, from Pikdum's commit this is reversed
    x = :crypto.hash(:sha, salt <> hash)
    verifier = :crypto.mod_pow(@g, x, @n)

    private_b = :crypto.strong_rand_bytes(19)
    {public_b, _} = :crypto.generate_key(:srp, {:host, [verifier, @g, @n, :"6"]}, private_b)

    unk3 = :crypto.strong_rand_bytes(16)

    response =
      <<0, 0, 0>> <>
        reverse(public_b) <> <<1, @g, 32>> <> reverse(@n) <> salt <> unk3 <> <<0>>

    IO.inspect(response, label: "Response", limit: :infinity)

    ThousandIsland.Socket.send(
      socket,
      response
    )

    {:continue,
     %{
       salt: salt,
       verifier: verifier,
       private_b: private_b,
       public_b: public_b,
       username: username
     }}
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
