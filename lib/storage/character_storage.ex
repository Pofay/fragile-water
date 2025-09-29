defmodule FragileWater.CharacterStorage do
  @player_characters :fragile_water_player_session_table

  def init do
    :ets.new(@player_characters, [:set, :public, :named_table])
  end

   def put(account_name, character) do
    case get(account_name) do
      [{_, characters}] -> :ets.insert(account_name, [character | characters])
      _ -> :ets.insert(account_name, [character])
    end
  end

  def get(account_name) do
    :ets.lookup(@player_characters, account_name)
  end
end
