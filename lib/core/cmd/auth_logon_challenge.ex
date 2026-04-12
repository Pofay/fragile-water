defmodule FragileWater.Core.Cmd.AuthLogonChallenge do
  @behaviour FragileWater.Core.Cmd.AuthHandler

  alias FragileWater.Core.Cmd.AuthHandler
  alias FragileWater.Core.AuthUtils

  import Binary, only: [reverse: 1]

  require Logger

  @cmd_auth_logon_challenge 0

  @impl AuthHandler
  def generate_payload(
        <<@cmd_auth_logon_challenge, _protocol_version::little-size(8), _size::little-size(16),
          _game_name::bytes-little-size(4), _version::bytes-little-size(3),
          _build::little-size(16), _platform::bytes-little-size(4), _os::bytes-little-size(4),
          _locale::bytes-little-size(4), _world_region_bias::little-size(32),
          _ip::little-size(32), account_name_length::unsigned-little-size(8),
          account_name::bytes-little-size(account_name_length)>>,
        _state
      ) do
    Logger.info("[AuthServer]: AUTH_LOGON_CHALLENGE for: #{account_name}")

    state = AuthUtils.logon_challenge_state(account_name)

    unk3 = :crypto.strong_rand_bytes(16)

    # From https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server
    packet =
      IO.iodata_to_binary([
        <<0, 0, 0>> <>
          reverse(state.public_b) <>
          <<1>> <>
          state.g <>
          <<32>> <>
          reverse(state.n) <>
          state.salt <>
          unk3 <>
          <<0>>
      ])

    Logger.info("[AuthServer]: Server Proof Generated")
    Logger.info("#{inspect(packet)}")

    {:continue, state, packet}
  end

  @impl AuthHandler
  def post_handle(state) do
    state
  end

  @impl AuthHandler
  def can_handle?(opcode) do
    opcode == @cmd_auth_logon_challenge
  end
end
