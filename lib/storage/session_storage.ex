defmodule FragileWater.SessionStorage do
  @player_session_table :fragile_water_player_session_table

  def init do
    :ets.new(@player_session_table, [:set, :public, :named_table])
  end

  def put(account_name, session) do
    :ets.insert(@player_session_table, {account_name, session})
  end

  def get(account_name) do
    :ets.lookup(@player_session_table, account_name)
  end
end
