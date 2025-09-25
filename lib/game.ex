defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  import Bitwise, only: [bxor: 2]

  alias FragileWater.CryptoSession
  alias FragileWater.SessionStorage

  @smsg_auth_challenge 0x1EC
  @cmsg_auth_session 0x1ED

  @cmsg_char_enum 0x037
  @smsg_char_enum 0x03B

  @smsg_auth_response 0x1EE

  @cmsg_ping 0x1DC
  @smsg_pong 0x1DD

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
        <<size::big-size(16), @cmsg_auth_session::little-size(32), body::binary-size(size - 4)>>,
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
      # World key might work inside an ETS Storage
      world_key = create_tbc_key(session)
      crypt = %{key: world_key, send_i: 0, send_j: 0, recv_i: 0, recv_j: 0}
      {:ok, crypto_pid} = CryptoSession.start_link(crypt)
      Logger.info("[GameServer] Crypto PID: #{inspect(crypto_pid)}")

      {packet, crypt} =
        build_packet(@smsg_auth_response, <<0x0C::little-size(32), 0, 0::little-size(32)>>, crypt)

      CryptoSession.update(crypto_pid, crypt)

      Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

      ThousandIsland.Socket.send(socket, packet)
      {:continue, Map.merge(state, %{username: username, crypto_pid: crypto_pid})}
    else
      Logger.error("[GameServer] Authentication failed for #{username}")
      {:close, state}
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(
        <<header::bytes-size(6), body::binary>>,
        socket,
        state
      ) do
    case decrypt_header(header, CryptoSession.get(state.crypto_pid)) do
      {<<_size::big-size(16), @cmsg_char_enum::little-size(32)>>, crypt} ->
        payload = <<0>>

        {packet, crypt} = build_packet(@smsg_char_enum, payload, crypt)
        Logger.info("[GameServer] Crypto PID: #{inspect(state.crypto_pid)}")
        CryptoSession.update(state.crypto_pid, crypt)

        Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

        ThousandIsland.Socket.send(socket, packet)

      {<<size::big-size(16), @cmsg_ping::little-size(32)>>, crypt} ->
        <<sequence_id::little-size(32), latency::little-size(32)>> = body
        payload = <<size, @smsg_pong::little-size(16), sequence_id>>
        Logger.info("[GameServer] CSMG PING - sequence_id: #{sequence_id}, latency: #{latency}")

        {packet, crypt} = build_packet(@smsg_char_enum, payload, crypt)
        Logger.info("[GameServer] Crypto PID: #{inspect(state.crypto_pid)}")
        CryptoSession.update(state.crypto_pid, crypt)

        Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

        ThousandIsland.Socket.send(socket, packet)
        {:continue, Map.merge(state, %{latency: latency})}

      other ->
        Logger.error("[GameServer] Unknown decrypted header: #{inspect(other)}")
    end

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

  defp decrypt_header(header, state) do
    acc = {<<>>, %{recv_i: state.recv_i, recv_j: state.recv_j}}

    {header, crypt_state} =
      Enum.reduce(
        :binary.bin_to_list(header),
        acc,
        fn byte, {header, crypt} ->
          recv_i = rem(crypt.recv_i, byte_size(state.key))
          x = bxor(byte - crypt.recv_j, :binary.at(state.key, recv_i))
          <<truncated_x>> = <<x::little-size(8)>>
          {header <> <<truncated_x>>, %{recv_i: recv_i + 1, recv_j: byte}}
        end
      )

    {header, Map.merge(state, crypt_state)}
  end

  defp create_tbc_key(session) do
    s_key =
      <<0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2,
        0xAA>>

    :crypto.mac(:hmac, :sha, s_key, session)
  end
end
