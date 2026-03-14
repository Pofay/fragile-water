import Config

config :fragile_water, ecto_repos: [FragileWater.DBC, FragileWater.Mangos]
config :fragile_water, FragileWater.DBC, database: "db/burning_crusade_dbcs.sqlite", log: false
config :fragile_water, FragileWater.Mangos, database: "db/mangos-tbc.sqlite", log: false
