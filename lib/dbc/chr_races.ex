defmodule FragileWater.DBC.ChrRaces do
  use Ecto.Schema

  @primary_key {:entry, :integer, autogenerate: false}
  schema "ChrRaces" do
    field(:flags, :integer)
    field(:faction_id, :integer)
    field(:exploration_sound_id, :integer)
    field(:male_display_id, :integer)
    field(:female_display_id, :integer)
    field(:client_prefix, :string)
    field(:mount_scale, :float)
    field(:base_language, :integer)
    field(:creature_type, :integer)
    field(:res_sickness_spell_id, :integer)
    field(:splash_sound_id, :integer)
    field(:client_file_string, :string)
    field(:cinematic_sequence_id, :integer)

    # Neutral names
    field(:name_en_gb, :string)
    field(:name_ko_kr, :string)
    field(:name_fr_fr, :string)
    field(:name_de_de, :string)
    field(:name_en_cn, :string)
    field(:name_en_tw, :string)
    field(:name_es_es, :string)
    field(:name_es_mx, :string)
    field(:name_ru_ru, :string)
    field(:name_ja_jp, :string)
    field(:name_pt_pt, :string)
    field(:name_it_it, :string)
    field(:name_unknown_12, :string)
    field(:name_unknown_13, :string)
    field(:name_unknown_14, :string)
    field(:name_unknown_15, :string)
    field(:name_flags, :integer)

    # Female names
    field(:name_female_en_gb, :string)
    field(:name_female_ko_kr, :string)
    field(:name_female_fr_fr, :string)
    field(:name_female_de_de, :string)
    field(:name_female_en_cn, :string)
    field(:name_female_en_tw, :string)
    field(:name_female_es_es, :string)
    field(:name_female_es_mx, :string)
    field(:name_female_ru_ru, :string)
    field(:name_female_ja_jp, :string)
    field(:name_female_pt_pt, :string)
    field(:name_female_it_it, :string)
    field(:name_female_unknown_12, :string)
    field(:name_female_unknown_13, :string)
    field(:name_female_unknown_14, :string)
    field(:name_female_unknown_15, :string)
    field(:name_female_flags, :integer)

    # Male names
    field(:name_male_en_gb, :string)
    field(:name_male_ko_kr, :string)
    field(:name_male_fr_fr, :string)
    field(:name_male_de_de, :string)
    field(:name_male_en_cn, :string)
    field(:name_male_en_tw, :string)
    field(:name_male_es_es, :string)
    field(:name_male_es_mx, :string)
    field(:name_male_ru_ru, :string)
    field(:name_male_ja_jp, :string)
    field(:name_male_pt_pt, :string)
    field(:name_male_it_it, :string)
    field(:name_male_unknown_12, :string)
    field(:name_male_unknown_13, :string)
    field(:name_male_unknown_14, :string)
    field(:name_male_unknown_15, :string)
    field(:name_male_flags, :integer)

    # Customization
    field(:facial_hair_customization_0, :string)
    field(:facial_hair_customization_1, :string)
    field(:hair_customization, :string)

    field(:required_expansion, :integer)
  end
end
