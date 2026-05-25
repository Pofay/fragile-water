defmodule FragileWater.Core.Msg.CharCreate do
  require Logger

  alias FragileWater.CharacterStorage
  alias FragileWater.Mangos
  alias FragileWater.Mangos.PlayerCreateInfo

  @cmsg_char_create 0x036
  @smsg_char_create 0x03A

  def handle(@cmsg_char_create, body, state) do
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

    packet = CharacterStorage.add_character(state.username, character)

    {@smsg_char_create, <<packet>>, state}
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

  defp extract_name_with_rest(packet) do
    case :binary.match(packet, <<0>>) do
      {idx, _len} ->
        name = :binary.part(packet, 0, idx)
        rest = :binary.part(packet, idx + 1, byte_size(packet) - (idx + 1))
        {name, rest}

      :nomatch ->
        {packet, <<>>}
    end
  end
end
