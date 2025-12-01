defmodule FragileWater.SessionStorage do
  require Logger
  alias FragileWater.WorldConnection

  @player_session_table :fragile_water_player_session_table
  @player_connection_table :fragile_water_player_connection_table

  def init do
    :ets.new(@player_session_table, [:set, :public, :named_table])
    :ets.new(@player_connection_table, [:set, :public, :named_table])
  end

  def put(account_name, session) do
    :ets.insert(@player_session_table, {account_name, session})
  end

  def get(account_name) do
    :ets.lookup(@player_session_table, account_name)
  end

  def create_connection(account_name, crypto) do
    case :ets.lookup(@player_connection_table, account_name) do
      [{_username, pid}] ->
        Logger.info("[GameServer] Existing PID: #{inspect(pid)}")
        WorldConnection.update(pid, crypto)
        {:ok, pid}

      _ ->
        {:ok, pid} = WorldConnection.start_link(crypto)
        :ets.insert(@player_connection_table, {account_name, pid})
        Logger.info("[GameServer] New PID: #{inspect(pid)}")
        {:ok, pid}
    end
  end
end
