defmodule FragileWater.CharacterStorage do
  @player_characters :fragile_water_player_characters_storage

  def init do
    :ets.new(@player_characters, [:set, :public, :named_table])
  end

  def add_character(username, character) do
    case get_characters(username) do
      {username, []} ->
        :ets.insert(@player_characters, {username, [character]})

      {username, characters} ->
        :ets.insert(@player_characters, {username, [character | characters]})
    end
  end

  def get_characters(username) do
    case :ets.lookup(@player_characters, username) do
      [{username, characters}] -> {username, characters}
      _ -> {username, []}
    end
  end
end
