defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  import Bitwise, only: [bxor: 2]

  alias FragileWater.CryptoSession
  alias FragileWater.SessionStorage
  alias FragileWater.CharacterStorage

  @smsg_auth_challenge 0x1EC
  @cmsg_auth_session 0x1ED

  @cmsg_char_enum 0x037
  @smsg_char_enum 0x03B

  @smsg_auth_response 0x1EE

  @cmsg_ping 0x1DC
  @smsg_pong 0x1DD

  @cmsg_realm_split 0x38C
  @smsg_realm_split 0x38B

  @cmsg_char_create 0x036
  @smsg_char_create 0x03A

  @impl ThousandIsland.Handler
  def handle_connection(socket, _state) do
    seed = :crypto.strong_rand_bytes(4)
    size = <<6::big-size(16)>>
    opcode = <<@smsg_auth_challenge::little-size(16)>>

    packet =
      size <>
        opcode <>
        seed

    Logger.info("[GameServer] SMSG_AUTH_CHALLENGE")
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
    Logger.info("[GameServer] CMSG_AUTH_SESSION")

    <<build::little-size(32), server_id::little-size(32), rest::binary>> = body
    {username, additional_bits} = extract_name_with_rest(rest)

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
      {<<size::big-size(16), opcode::little-size(32)>>, crypt} ->
        handle_world_packet(opcode, size, body, crypt, state, socket)

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

  defp extract_name_with_rest(payload) do
    case :binary.match(payload, <<0>>) do
      {idx, _len} ->
        name = :binary.part(payload, 0, idx)
        rest = :binary.part(payload, idx + 1, byte_size(payload) - (idx + 1))
        {name, rest}

      :nomatch ->
        {payload, <<>>}
    end
  end

  defp handle_world_packet(opcode, size, body, crypt, state, socket) do
    case opcode do
      @cmsg_char_enum ->
        Logger.info("[GameServer] CMSG_CHAR_ENUM")

        {_username, characters} = CharacterStorage.get_characters(state.username)
        length = Enum.count(characters)

        Logger.info("[GameServer] Characters: #{inspect(characters)}")

        characters_payload = Enum.map(characters, &build_character_enum_data(&1))

        payload =
          case length do
            0 -> <<0>>
            _ -> <<length>> <> Enum.join(characters_payload)
          end

        Logger.info(
          "[GameServer] Number of Characters for #{state.username}: #{Enum.count(characters)}"
        )

        Enum.each(characters, fn c ->
          Logger.info("[GameServer] Character name: #{c.name}")
        end)

        {packet, crypt} = build_packet(@smsg_char_enum, payload, crypt)
        CryptoSession.update(state.crypto_pid, crypt)
        Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

        ThousandIsland.Socket.send(socket, packet)
        {:continue, state}

      @cmsg_ping ->
        Logger.info("[GameServer] CMSG_PING")

        <<sequence_id::little-size(32), latency::little-size(32)>> = body
        payload = <<size, @smsg_pong::little-size(16), sequence_id>>

        {packet, crypt} = build_packet(@smsg_char_enum, payload, crypt)
        CryptoSession.update(state.crypto_pid, crypt)

        Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

        ThousandIsland.Socket.send(socket, packet)

        {:continue, Map.merge(state, %{latency: latency})}

      @cmsg_char_create ->
        Logger.info("[GameServer] CMSG_CHAR_CREATE")

        {character_name, char_rest} = extract_name_with_rest(body)

        <<race, class, gender, skin, face, hair_style, hair_color, facial_hair, outfit_id>> =
          char_rest

        character = %{
          guid: :binary.decode_unsigned(:crypto.strong_rand_bytes(64)),
          name: character_name,
          race: race,
          class: class,
          gender: gender,
          skin: skin,
          face: face,
          hair_style: hair_style,
          hair_color: hair_color,
          facial_hair: facial_hair,
          outfit_id: outfit_id,
          level: 1,
          area: 85,
          map: 0,
          x: 1676.71,
          y: 1678.31,
          z: 121.67,
          orientation: 2.7056
        }

        Logger.info("[GameServer] Character Created: #{inspect(character, limit: :infinity)}")

        CharacterStorage.add_character(state.username, character)
        {packet, crypt} = build_packet(@smsg_char_create, <<0x2F>>, crypt)
        CryptoSession.update(state.crypto_pid, crypt)

        ThousandIsland.Socket.send(socket, packet)

        {:continue, state}

      @cmsg_realm_split ->
        Logger.info("[GameServer] CMSG_REALM_SPLIT")

        <<unk::little-unsigned-integer-size(32), _rest::binary>> = body
        split_date = "01/01/01" <> <<0>>
        realm_split_state = 0

        payload =
          <<unk::little-unsigned-integer-size(32)>> <>
            <<realm_split_state::little-unsigned-integer-size(32)>> <>
            split_date

        {packet, crypt} = build_packet(@smsg_realm_split, payload, crypt)
        CryptoSession.update(state.crypto_pid, crypt)

        Logger.info("[GameServer] Packet: #{inspect(packet, limit: :infinity)}")

        ThousandIsland.Socket.send(socket, packet)
        {:continue, state}

      _ ->
        Logger.error("[GameServer] Unimplemented opcode: #{inspect(opcode, base: :hex)}")
        {:continue, state}
    end
  end

  defp build_character_enum_data(character) do
    # GUID (8 bytes)
    guid_bytes = <<character.guid::little-size(64)>>

    # Name (null-terminated string)
    name_bytes = character.name <> <<0>>

    # Basic character info
    race_class_gender = <<character.race, character.class, character.gender>>

    # Player bytes (skin, face, hair style, hair color combined)
    player_bytes = <<character.skin, character.face, character.hair_style, character.hair_color>>

    # Player bytes2 (facial hair, bank slots, etc.)
    # facial_hair + 3 padding bytes
    player_bytes2 = <<character.facial_hair, 0, 0, 0>>

    # Level
    level_bytes = <<character.level>>

    # Zone ID (4 bytes)
    zone_bytes = <<character.area::little-size(32)>>

    # Map ID (4 bytes)
    map_bytes = <<character.map::little-size(32)>>

    # Position (3 floats, 4 bytes each)
    position_bytes =
      <<character.x::little-float-size(32)>> <>
        <<character.y::little-float-size(32)>> <>
        <<character.z::little-float-size(32)>>

    # Guild ID (4 bytes) - 0 if no guild
    guild_bytes = <<0::little-size(32)>>

    # Player flags (4 bytes)
    flags_bytes = <<0::little-size(32)>>

    # At login flags (4 bytes)
    at_login_bytes = <<0::little-size(32)>>

    # Pet info (12 bytes total)
    # 4 bytes
    pet_display_id = <<0::little-size(32)>>
    # 4 bytes
    pet_level = <<0::little-size(32)>>
    # 4 bytes
    pet_family = <<0::little-size(32)>>

    # Equipment cache - this is complex, for now send empty (19 * 8 = 152 bytes)
    # Each equipment slot needs: item_id(4) + display_id(4) = 8 bytes
    # 19 equipment slots total
    equipment_cache = String.duplicate(<<0>>, 152)

    # Combine all parts
    guid_bytes <>
      name_bytes <>
      race_class_gender <>
      player_bytes <>
      player_bytes2 <>
      level_bytes <>
      zone_bytes <>
      map_bytes <>
      position_bytes <>
      guild_bytes <>
      flags_bytes <>
      at_login_bytes <>
      pet_display_id <>
      pet_level <>
      pet_family <>
      equipment_cache
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
