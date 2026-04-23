defmodule FragileWater.Core.CharacterUtils do
  import FragileWater.Core.BinaryUtils, only: [extract_name_with_rest: 1]

  def parse_char_create_body(body) do
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

  def build_character_enum_data(character) do
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
    chest = Mangos.get(ItemTemplate, 22_416)
    legs = Mangos.get(ItemTemplate, 22_417)
    head = Mangos.get(ItemTemplate, 22_418)
    shoulders = Mangos.get(ItemTemplate, 22_419)
    feet = Mangos.get(ItemTemplate, 22_420)
    hands = Mangos.get(ItemTemplate, 22_421)
    waist = Mangos.get(ItemTemplate, 22_422)
    wrist = Mangos.get(ItemTemplate, 22_423)

    # Dory's Embrace, Corrupted Ashbringer, Thoridal and Alliance Tabard
    back = Mangos.get(ItemTemplate, 33_484)
    main_hand = Mangos.get(ItemTemplate, 22_691)
    ranged = Mangos.get(ItemTemplate, 34_334)
    tabard = Mangos.get(ItemTemplate, 15_196)

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
