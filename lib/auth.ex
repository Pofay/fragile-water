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
  # From https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Client
  def handle_data(
        <<@cmd_auth_logon_challenge, protocol_version::little-size(8), _size::little-size(16),
          _game_name::bytes-little-size(4), _version::bytes-little-size(3),
          _build::little-size(16), _platform::bytes-little-size(4), _os::bytes-little-size(4),
          _locale::bytes-little-size(4), _world_region_bias::little-size(32),
          _ip::little-size(32), account_name_length::unsigned-little-size(8),
          account_name::bytes-little-size(account_name_length)>>,
        socket,
        _state
      ) do
    Logger.info("[Authentication: LOGON CHALLENGE] #{account_name}")
    Logger.info("[Authentication: LOGON CHALLENGE] Version: #{protocol_version}")

    state = logon_challenge_state(account_name)

    unk3 = :crypto.strong_rand_bytes(16)

    # From https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server
    packet =
      <<0, 0, 0>> <>
        reverse(state.public_b) <>
        <<1>> <>
        state.g <>
        <<32>> <>
        reverse(state.n) <>
        state.salt <>
        unk3 <>
        <<0>>

    Logger.info("[Authentication: LOGON CHALLENGE] Server Proof Generated")
    Logger.info("#{inspect(packet)}")

    ThousandIsland.Socket.send(
      socket,
      packet
    )

    {:continue, state}
  end

  @impl ThousandIsland.Handler
  # From https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Client
  def handle_data(
        <<@cmd_auth_logon_proof, client_public_key::little-bytes-size(32),
          client_proof::little-bytes-size(20), _crc_hash::little-bytes-size(20),
          _number_of_keys::little-size(8), _security_flags::little-size(8)>>,
        socket,
        state
      ) do
    Logger.info("Authentication: LOGON PROOF #{state.account_name}")
    Logger.info("Client Proof: #{inspect(client_proof)}")
    Logger.info("state: #{inspect(state)}")

    public_a = reverse(client_public_key)
    scrambler = :crypto.hash(:sha, reverse(public_a) <> reverse(state.public_b))

    compute_key =
      :crypto.compute_key(
        :srp,
        public_a,
        {state.public_b, state.private_b},
        {:host, [state.verifier, @n, :"6", reverse(scrambler)]}
      )

    s = reverse(compute_key)

    session = interleave(s)

    mod_hash = :crypto.hash(:sha, reverse(@n))
    generator_hash = :crypto.hash(:sha, @g)

    t3 = :crypto.exor(mod_hash, generator_hash)
    t4 = :crypto.hash(:sha, state.account_name)

    m =
      :crypto.hash(
        :sha,
        t3 <> t4 <> state.salt <> reverse(public_a) <> reverse(state.public_b) <> session
      )

    Logger.info("LOGON PROOF: Verifying client proof for #{state.account_name}")
    Logger.info("Generated M1: #{inspect(m)}")

    if m == client_proof do
      Logger.info("LOGON PROOF: Client proof matched for #{state.account_name}")

      server_proof = :crypto.hash(:sha, reverse(public_a) <> client_proof <> session)

      state =
        Map.merge(state, %{public_a: public_a, session: session, server_proof: server_proof})

      # From https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Server
      packet =
        <<1, 0>> <>
          state.server_proof <>
          <<0, 0, 128, 0>> <>
          <<0, 0, 0, 0>> <>
          <<0, 0>>

      ThousandIsland.Socket.send(socket, packet)
      Logger.info("#{inspect(packet)}")
      {:continue, state}
    else
      Logger.error("Client proof does not match!")
      Logger.info("public_a: #{inspect(public_a)}")
      Logger.info("client_proof: #{inspect(client_proof)}")
      Logger.info("m: #{inspect(m)}")

      ThousandIsland.Socket.send(socket, <<0, 0, 5>>)
      {:close, state}
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(<<opcode, _packet::binary>>, socket, state) do
    IO.inspect("UNHANDLED opcode: #{opcode}")
    ThousandIsland.Socket.send(socket, <<0, 0, 5>>)
    {:close, state}
  end

  defp interleave(s) do
    list = Binary.to_list(s)

    t1 = Binary.from_list(interleave_t1(list))
    t2 = Binary.from_list(interleave_t2(list))

    t1_hash = Binary.to_list(:crypto.hash(:sha, t1))
    t2_hash = Binary.to_list(:crypto.hash(:sha, t2))

    Enum.zip([t1_hash, t2_hash])
    |> Enum.map(&Tuple.to_list/1)
    |> List.flatten()
    |> Binary.from_list()
  end

  defp interleave_t1([a, _ | rest]), do: [a | interleave_t1(rest)]
  defp interleave_t1([]), do: []

  defp interleave_t2([_, b | rest]), do: [b | interleave_t2(rest)]
  defp interleave_t2([]), do: []

  defp calculate_private_b(state) do
    private_b = :crypto.strong_rand_bytes(19)
    Map.merge(state, %{private_b: private_b})
  end

  defp calculate_public_b(state) do
    IO.inspect(state)

    {public_b, _} =
      :crypto.generate_key(
        :srp,
        {:host, [state.verifier, state.g, state.n, :"6"]},
        state.private_b
      )

    Map.merge(state, %{public_b: public_b})
  end

  defp account_state(account) do
    salt = :crypto.strong_rand_bytes(32)
    hash = :crypto.hash(:sha, String.upcase(@username) <> ":" <> String.upcase(@password))
    x = reverse(:crypto.hash(:sha, salt <> hash))

    %{n: @n, g: @g}
    |> Map.merge(%{account_name: account})
    |> Map.merge(%{
      verifier: :crypto.mod_pow(@g, x, @n)
    })
    |> Map.merge(%{salt: salt})
  end

  defp logon_challenge_state(account) do
    account_state(account)
    |> calculate_private_b
    |> calculate_public_b
  end
end
