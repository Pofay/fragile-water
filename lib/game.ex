defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  import Bitwise, only: [bxor: 2]

  alias FragileWater.SessionStorage

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

    <<client_seed::little-bytes-size(4), client_proof::little-bytes-size(20), _bits::binary>> =
      additional_bits

    Logger.info(
      "[GameServer] Received CMSG_AUTH_SESSION with build: #{build} and server_id: #{server_id}"
    )

    Logger.info("[GameServer] Username: #{username}")

    {username, session} = hd(SessionStorage.get(username))

    data =
      username <>
        <<0::little-size(32)>> <>
        client_seed <>
        state.seed <>
        session

    Logger.info("[GameServer]  Key size is: #{inspect(byte_size(session))}")

    server_proof = :crypto.hash(:sha, data)

    if client_proof == server_proof do
      Logger.info("[GameServer] Authentication Successful for #{username}")

      # TBC/Wrath uses an HMAC1SHA for its World Encryption Key
      # This definitely needs to be tracked by another Process/GenServer
      world_key = create_tbc_key(session)
      crypt = %{key: world_key, send_i: 0, send_j: 0, recv_i: 0, recv_j: 0}

      {packet, crypt} =
        build_packet(0x1EE, <<0x0C::little-size(32), 0, 0::little-size(32)>>, crypt)

      Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

      ThousandIsland.Socket.send(socket, packet)
      {:continue, Map.merge(state, %{username: username, crypt: crypt})}
    else
      Logger.error("[GameServer] Authentication failed for #{username}")
      {:close, state}
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(
        <<_size::big-size(16), opcode::little-size(32)>>,
        _socket,
        state
      ) do
    Logger.error("[GameServer] Received OPCODE FOR CMSG_CHAR_ENUM: #{inspect(opcode)}")
    {:continue, state}
  end

  @impl ThousandIsland.Handler
  def handle_data(
        packet,
        _socket,
        state
      ) do
    Logger.error("[GameServer] Unhandled packet: #{inspect(packet, limit: :infinity)})}")
    {:continue, state}
  end

  defp extract_username_with_rest(payload) do
    case :binary.match(payload, <<0>>) do
      {idx, _len} ->
        username = :binary.part(payload, 0, idx)
        rest = :binary.part(payload, idx + 1, byte_size(payload) - (idx + 1))
        {username, rest}

      :nomatch ->
        {payload, <<>>}
    end
  end

  defp build_packet(opcode, payload, crypt) do
    size = byte_size(payload) + 2
    header = <<size::big-size(16), opcode::little-size(16)>>

    Logger.info(
      "[GameServer] Encrypting header: #{inspect(header)} with crypt: #{inspect(crypt)}"
    )

    {encrypted_header, new_crypt} = encrypt_header(header, crypt)

    Logger.info(
      "[GameServer] Encrypted header: #{inspect(encrypted_header)} with new crypt: #{inspect(new_crypt)}"
    )

    {encrypted_header <> payload, new_crypt}
  end

  defp encrypt_header(header, state) do
    acc = {<<>>, %{send_i: state.send_i, send_j: state.send_j}}

    {header, crypt_state} =
      Enum.reduce(:binary.bin_to_list(header), acc, fn byte, {header, crypt} ->
        send_i = rem(crypt.send_i, byte_size(state.key))
        x = bxor(byte, :binary.at(state.key, send_i)) + crypt.send_j
        <<truncated_x>> = <<x::little-size(8)>>
        {header <> <<truncated_x>>, %{send_i: send_i + 1, send_j: truncated_x}}
      end)

    {header, Map.merge(state, crypt_state)}
  end

  defp create_tbc_key(session) do
    s_key =
      <<0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2,
        0xAA>>

    :crypto.mac(:hmac, :sha, s_key, session)
  end
end
