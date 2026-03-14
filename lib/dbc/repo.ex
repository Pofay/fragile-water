defmodule FragileWater.DBC do
  use Ecto.Repo, otp_app: :fragile_water, adapter: Ecto.Adapters.SQLite3
end
