defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  alias FragileWater.Session
  alias FragileWater.SessionKeyStorage
  alias FragileWater.CharacterStorage
  alias FragileWater.Encryption

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

    {username, session} = hd(SessionKeyStorage.get(username))

    data =
      username <>
        <<0::little-size(32)>> <>
        client_seed <>
        state.seed <>
        session

    server_proof = :crypto.hash(:sha, data)

    if client_proof == server_proof do
      Logger.info("[GameServer] Authentication Successful for #{username}")

      world_key = Encryption.create_tbc_key(session)
      Logger.info("[GameServer] Key size for TBC is: #{inspect(byte_size(world_key))}")

      crypt = %{key: world_key, send_i: 0, send_j: 0, recv_i: 0, recv_j: 0}
      {:ok, crypto_pid} = Session.start_link(crypt)
      Logger.info("[GameServer] Crypto PID: #{inspect(crypto_pid)}")

      # From https://gtker.com/wow_messages/docs/smsg_auth_response.html#client-version-243
      payload =
        <<0x0C::little-size(32)>> <>
          <<0>> <>
          <<0::little-size(32)>> <>
          <<0>> <>
          <<1>>

      send_packet(crypto_pid, @smsg_auth_response, socket, payload)

      {:continue, Map.merge(state, %{username: username, crypto_pid: crypto_pid})}
    else
      Logger.error("[GameServer] Authentication failed for #{username}")
      {:close, state}
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(
        data,
        socket,
        state
      ) do
    state = Map.put(state, :packet_stream, Map.get(state, :packet_stream, <<>>) <> data)
    handle_packet(socket, state)
  end

  def handle_packet(socket, %{packet_stream: <<header::bytes-size(6), body::binary>>} = state) do
    with {:ok, body_size, opcode} <-
           Session.enqueue_packets(state.crypto_pid, header),
         {:ok, payload, remaining} <- extract_payload(body, body_size) do
      Session.commit_enqueued_packets(state.crypto_pid)
      state = Map.put(state, :packet_stream, remaining)

      {:continue, new_state} = handle_world_packet(opcode, body_size + 4, payload, state, socket)

      if byte_size(remaining) >= 6 do
        handle_packet(socket, new_state)
      else
        {:continue, new_state}
      end
    else
      # Invalid header (size < 4) - log error and close connection
      {:error, :invalid_header} ->
        Logger.error("[GameServer] Invalid packet header received")
        {:close, state}

      :incomplete_payload ->
        Logger.info("[GameServer] Received incomplete payload. Buffering...")
        {:continue, state}
    end
  end

  def handle_packet(_socket, state), do: {:continue, state}

  defp extract_payload(body, body_size) when byte_size(body) >= body_size do
    <<payload::binary-size(body_size), remaining::binary>> = body
    {:ok, payload, remaining}
  end

  defp extract_payload(_body, _body_size), do: :incomplete_payload

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

  defp handle_world_packet(opcode, size, body, state, socket) do
    case opcode do
      @cmsg_char_enum ->
        Logger.info("[GameServer] CMSG_CHAR_ENUM")

        {_username, characters} = CharacterStorage.get_characters(state.username)
        length = Enum.count(characters)

        Logger.info("[GameServer] CMSG_CHAR_ENUM Number of Characters: #{inspect(length)}")

        characters_payload =
          Enum.map(characters, &build_character_enum_data(&1))

        payload =
          case length do
            0 -> <<0>>
            _ -> <<length>> <> Enum.join(characters_payload)
          end

        send_packet(
          state.crypto_pid,
          @smsg_char_enum,
          socket,
          payload
        )

        {:continue, state}

      @cmsg_ping ->
        Logger.info("[GameServer] CMSG_PING")

        <<sequence_id::little-size(32), latency::little-size(32)>> = body
        Logger.info("[GameServer] CMSG_PING: sequence_id: #{sequence_id}, latency: #{latency}")

        payload = <<sequence_id::little-size(32)>>

        send_packet(
          state.crypto_pid,
          @smsg_pong,
          socket,
          payload
        )

        {:continue, Map.merge(state, %{latency: latency})}

      @cmsg_char_create ->
        Logger.info("[GameServer] CMSG_CHAR_CREATE")

        character_data = parse_char_create_body(body)

        character = %{
          guid: :binary.decode_unsigned(:crypto.strong_rand_bytes(64)),
          name: character_data.name,
          race: character_data.race,
          class: character_data.char_class,
          gender: character_data.gender,
          skin: character_data.skin,
          face: character_data.face,
          hair_style: character_data.hair_style,
          hair_color: character_data.hair_color,
          facial_hair: character_data.facial_hair,
          outfit_id: character_data.outfit_id,
          level: 1,
          area: 85,
          map: 0,
          x: 1676.71,
          y: 1678.31,
          z: 121.67,
          orientation: 2.7056
        }

        payload = CharacterStorage.add_character(state.username, character)

        send_packet(
          state.crypto_pid,
          @smsg_char_create,
          socket,
          <<payload>>
        )

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

        send_packet(
          state.crypto_pid,
          @smsg_realm_split,
          socket,
          payload
        )

        {:continue, state}

      _ ->
        Logger.error("[GameServer] Unimplemented opcode: #{inspect(opcode, base: :hex)}")
        {:continue, state}
    end
  end

  defp parse_char_create_body(body) do
    {name, rest} = extract_name_with_rest(body)

    <<race, char_class, gender, skin, face, hair_style, hair_color, facial_hair, outfit_id,
      _rest::binary>> =
      rest

    %{
      name: name,
      race: race,
      char_class: char_class,
      gender: gender,
      skin: skin,
      face: face,
      hair_style: hair_style,
      hair_color: hair_color,
      facial_hair: facial_hair,
      outfit_id: outfit_id
    }
  end

  defp build_character_enum_data(character) do
    # From https://gtker.com/wow_messages/docs/smsg_char_enum.html#client-version-243
    # https://github.com/gtker/wow_messages/blob/main/wow_message_parser/wowm/world/character_screen/smsg_char_enum_2_4_3.wowm#L3

    character_data =
      <<character.guid::little-size(64)>> <>
        (character.name <> <<0>>) <>
        <<character.race, character.class, character.gender>> <>
        <<character.skin, character.face, character.hair_style, character.hair_color,
          character.facial_hair>> <>
        <<character.level>> <>
        <<character.area::little-size(32)>> <>
        <<character.map::little-size(32)>> <>
        <<character.x::little-float-size(32)>> <>
        <<character.y::little-float-size(32)>> <>
        <<character.z::little-float-size(32)>> <>
        <<0::little-size(32)>> <>
        <<0::little-size(32)>> <>
        <<0>> <>
        <<0::little-size(32)>> <>
        <<0::little-size(32)>> <>
        <<0::little-size(32)>>

    equipment_data = build_tbc_equipment()

    final_data = character_data <> equipment_data

    final_data
  end

  defp build_tbc_equipment() do
    # TBC has enchantment value
    # Vanilla includes Bag data
    # At https://github.com/gtker/wow_messages/blob/main/wow_message_parser/wowm/world/character_screen/smsg_char_enum_2_4_3.wowm#L3

    equipment_slots =
      Enum.map(0..19, fn _slot ->
        <<0::little-size(32)>> <>
          <<0>> <>
          <<0::little-size(32)>>
      end)

    equipment_data = Enum.join(equipment_slots)

    equipment_data
  end

  defp send_packet(crypto_pid, opcode, socket, payload) do
    {:ok, header} = Session.encrypt_header(crypto_pid, opcode, payload)
    ThousandIsland.Socket.send(socket, header <> payload)
  end
end
