defmodule FragileWater.Game do
  use ThousandIsland.Handler
  require Logger

  alias FragileWater.Session
  alias FragileWater.SessionKeyStorage
  alias FragileWater.CharacterStorage
  alias FragileWater.Encryption
  alias FragileWater.Mangos
  alias FragileWater.Mangos.ItemTemplate
  alias FragileWater.Mangos.PlayerCreateInfo

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

  @cmsg_player_login 0x03D
  @smsg_login_verify_world 0x236
  @smsg_tutorial_flags 0x0FD
  @smsg_update_object 0x0A9

  @impl ThousandIsland.Handler
  def handle_connection(socket, _state) do
    seed = :crypto.strong_rand_bytes(4)
    size = <<6::big-size(16)>>
    opcode = <<@smsg_auth_challenge::little-size(16)>>

    packet =
      IO.iodata_to_binary([
        size,
        opcode,
        seed
      ])

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
      IO.iodata_to_binary([
        username,
        <<0::little-size(32)>>,
        client_seed,
        state.seed,
        session
      ])

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
        IO.iodata_to_binary([
          <<0x0C::little-size(32)>>,
          <<0>>,
          <<0::little-size(32)>>,
          <<0>>,
          <<1>>
        ])

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
            _ -> IO.iodata_to_binary([<<length>>, Enum.join(characters_payload)])
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

        additional_info =
          Mangos.get_by(PlayerCreateInfo,
            race: character_data.race,
            class: character_data.char_class
          )

        character = %{
          guid: :binary.decode_unsigned(:crypto.strong_rand_bytes(8)),
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
          area: additional_info.zone,
          map: additional_info.map,
          x: additional_info.position_x,
          y: additional_info.position_y,
          z: additional_info.position_z,
          orientation: additional_info.orientation
        }

        payload = CharacterStorage.add_character(state.username, character)

        send_packet(
          state.crypto_pid,
          @smsg_char_create,
          socket,
          <<payload>>
        )

        {:continue, state}

      @cmsg_player_login ->
        <<character_guid::little-size(64)>> = body
        Logger.info("[GameServer] CMSG_PLAYER_LOGIN: character_guid: #{character_guid}")

        character = CharacterStorage.get_by_guid(state.username, character_guid)
        race = DBC.get_by(ChrRaces, id: character.race)

        unit_display_id =
          case character.gender do
            0 -> character.male_display
            1 -> character.female_display
          end

        IO.inspect(character)

        payload =
          IO.iodata_to_binary([
            <<character.map::little-size(32)>>,
            <<character.x::little-float-size(32)>>,
            <<character.y::little-float-size(32)>>,
            <<character.z::little-float-size(32)>>,
            <<character.orientation::little-float-size(32)>>
          ])

        send_packet(
          state.crypto_pid,
          @smsg_login_verify_world,
          socket,
          payload
        )

        send_packet(
          state.crypto_pid,
          @smsg_tutorial_flags,
          socket,
          <<0::little-size(256)>>
        )

        packet =
          <<
            # amount_of_objects: u32
            1,
            0,
            0,
            0
          >> <>
            <<
              # has_transport: u8
              0
            >> <>
            <<
              # update type = CREATE_OBJECT2
              3
            >> <>
            <<
              # packed guid, guid = 4
              1,
              4
            >> <>
            <<
              # object type = PLAYER
              4
            >> <>
            <<
              # update flags: SELF | ALL | LIVING = 0x31 (49) - u8
              49
            >> <>
            <<
              # === LIVING MOVEMENT DATA ===
              # MovementFlags: u32 = NONE
              0,
              0,
              0,
              0
            >> <>
            <<
              # extra_flags: u8
              0
            >> <>
            <<
              # timestamp: u32
              0,
              0,
              0,
              0
            >> <>
            <<character.x::little-float-size(32)>> <>
            <<character.y::little-float-size(32)>> <>
            <<character.z::little-float-size(32)>> <>
            <<character.orientation::little-float-size(32)>> <>
            <<
              # fall time (0.0)
              0,
              0,
              0,
              0
            >> <>
            <<
              # walk speed (1.0)
              0,
              0,
              128,
              63
            >> <>
            <<
              # run speed (7.0)
              0,
              0,
              224,
              64
            >> <>
            <<
              # run back speed (4.5)
              0,
              0,
              144,
              64
            >> <>
            <<
              # swim speed (0.0)
              0,
              0,
              0,
              0
            >> <>
            <<
              # flying speed (0.0)
              0,
              0,
              0,
              0
            >> <>
            <<
              # backwards flying speed (0.0)
              0,
              0,
              0,
              0
            >> <>
            <<
              # backwards swim speed (0.0)
              0,
              0,
              0,
              0
            >> <>
            <<
              # turn rate (pi ≈ 3.14159)
              219,
              15,
              73,
              64
            >> <>
            <<
              # === ALL flag payload: unknown2 u32 ===
              0,
              0,
              0,
              0
            >> <>
            <<
              # === UPDATE FIELDS ===
              # number of mask blocks: u8 = 5
              5
            >> <>
            <<
              # mask block 0: offsets 0,1,2,4,22,28 = 0x10400017
              0x17,
              0x00,
              0x40,
              0x10
            >> <>
            <<
              # mask block 1: offsets 34(bit2),35(bit3),36(bit4) = 0x0000001C
              0x1C,
              0x00,
              0x00,
              0x00
            >> <>
            <<
              # mask block 2: empty
              0x00,
              0x00,
              0x00,
              0x00
            >> <>
            <<
              # mask block 3: empty
              0x00,
              0x00,
              0x00,
              0x00
            >> <>
            <<
              # mask block 4: offsets 152(bit24),153(bit25) = 0x03000000
              0x00,
              0x00,
              0x00,
              0x03
            >> <>
            <<
              # --- VALUES in offset order ---

              # offset 0: OBJECT_GUID low = 4
              4,
              0,
              0,
              0
            >> <>
            <<
              # offset 1: OBJECT_GUID high = 0
              0,
              0,
              0,
              0
            >> <>
            <<
              # offset 2: OBJECT_TYPE = 0x19 (OBJECT|UNIT|PLAYER = 1|8|16)
              25,
              0,
              0,
              0
            >> <>
            <<
              # offset 4: OBJECT_SCALE_X = 1.0f
              0,
              0,
              128,
              63
            >> <>
            <<
              # offset 22: UNIT_HEALTH = 100
              100,
              0,
              0,
              0
            >> <>
            <<
              # offset 28: UNIT_MAXHEALTH = 100
              100,
              0,
              0,
              0
            >> <>
            <<
              # offset 34: UNIT_LEVEL = 1
              1,
              0,
              0,
              0
            >> <>
            <<
              # offset 35: UNIT_FACTIONTEMPLATE = 1
              1,
              0,
              0,
              0
            >> <>
            <<
              # offset 36: UNIT_BYTES_0 (race, class, gender, power)
              character.race,
              character.class,
              character.gender,
              1
            >> <>
            <<
              # offset 152: UNIT_DISPLAYID = 49 (male human)
              unit_display_id,
              0,
              0,
              0
            >> <>
            <<
              # offset 153: UNIT_NATIVEDISPLAYID = 50
              unit_display_id,
              0,
              0,
              0
            >>

        send_packet(state.crypto_pid, @smsg_update_object, socket, packet)

        {:continue, state}

      @cmsg_realm_split ->
        Logger.info("[GameServer] CMSG_REALM_SPLIT")

        <<unk::little-unsigned-integer-size(32), _rest::binary>> = body
        split_date = IO.iodata_to_binary(["01/01/01", 0])
        realm_split_state = 0

        payload =
          IO.iodata_to_binary([
            <<unk::little-unsigned-integer-size(32)>>,
            <<realm_split_state::little-unsigned-integer-size(32)>>,
            split_date
          ])

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
      IO.iodata_to_binary([
        <<character.guid::little-size(64)>>,
        <<character.name::binary, 0>>,
        <<character.race, character.class, character.gender>>,
        <<character.skin, character.face, character.hair_style, character.hair_color,
          character.facial_hair>>,
        <<character.level>>,
        <<character.area::little-size(32)>>,
        <<character.map::little-size(32)>>,
        <<character.x::little-float-size(32)>>,
        <<character.y::little-float-size(32)>>,
        <<character.z::little-float-size(32)>>,
        <<0::little-size(32)>>,
        <<0::little-size(32)>>,
        <<0>>,
        <<0::little-size(32)>>,
        <<0::little-size(32)>>,
        <<0::little-size(32)>>,
        build_tbc_equipment()
      ])

    character_data
  end

  defp build_tbc_equipment() do
    # Example for Dreadnaught battlegear:
    chest = Mangos.get(ItemTemplate, 22416)
    legs = Mangos.get(ItemTemplate, 22417)
    head = Mangos.get(ItemTemplate, 22418)
    shoulders = Mangos.get(ItemTemplate, 22419)
    feet = Mangos.get(ItemTemplate, 22420)
    hands = Mangos.get(ItemTemplate, 22421)
    waist = Mangos.get(ItemTemplate, 22422)
    wrist = Mangos.get(ItemTemplate, 22423)

    # Dory's Embrace, Corrupted Ashbringer, Thoridal and Alliance Tabard
    back = Mangos.get(ItemTemplate, 33484)
    main_hand = Mangos.get(ItemTemplate, 22691)
    ranged = Mangos.get(ItemTemplate, 34334)
    tabard = Mangos.get(ItemTemplate, 15196)

    equipment_slots =
      IO.iodata_to_binary([
        display_character_gear(head.display_id, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(shoulders.display_id, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(chest.display_id, 0, 0),
        display_character_gear(waist.display_id, 0, 0),
        display_character_gear(legs.display_id, 0, 0),
        display_character_gear(feet.display_id, 0, 0),
        display_character_gear(wrist.display_id, 0, 0),
        display_character_gear(hands.display_id, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(back.display_id, 0, 0),
        display_character_gear(main_hand.display_id, 0, 0),
        display_character_gear(0, 0, 0),
        display_character_gear(ranged.display_id, 0, 0),
        display_character_gear(tabard.display_id, 0, 0),
        display_character_gear(0, 0, 0)
      ])

    equipment_slots
  end

  defp send_packet(crypto_pid, opcode, socket, payload) do
    {:ok, header} = Session.encrypt_header(crypto_pid, opcode, payload)
    ThousandIsland.Socket.send(socket, IO.iodata_to_binary([header, payload]))
  end

  defp display_character_gear(display_id, inventory_type, enchantment) do
    # TBC has enchantment value while Vanilla doesn't have it.
    # At https://github.com/gtker/wow_messages/blob/main/wow_message_parser/wowm/world/character_screen/smsg_char_enum_2_4_3.wowm#L3

    # struct CharacterGear {
    # u32 equipment_display_id;
    # InventoryType inventory_type;
    # u32 enchantment;
    # }
    IO.iodata_to_binary([
      <<display_id::little-size(32)>>,
      <<inventory_type>>,
      <<enchantment::little-size(32)>>
    ])
  end
end
