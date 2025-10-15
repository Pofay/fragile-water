defmodule FragileWater.CharacterStorage do
  @player_characters :fragile_water_player_characters_storage

  @char_create_success 0x2F
  @char_create_server_limit 0x35

  def init do
    :ets.new(@player_characters, [:set, :public, :named_table])
  end

  def add_character(username, character) do
    case get_characters(username) do
      {_username, []} ->
        :ets.insert(@player_characters, {username, [character]})
        @char_create_success

      {_username, characters} when length(characters) >= 10 ->
        @char_create_server_limit

      {username, characters} ->
        :ets.insert(@player_characters, {username, characters ++ [character]})
        @char_create_success
    end
  end

  def get_characters(username) do
    case :ets.lookup(@player_characters, username) do
      [{username, characters}] -> {username, characters}
      _ -> {username, []}
    end
  end
end
