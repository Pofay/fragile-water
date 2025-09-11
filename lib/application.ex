defmodule FragileWater.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # {ThousandIsland, port: 3724, handler_module: FragileWater.AuthProxy}
      {ThousandIsland, port: 3724, handler_module: FragileWater.Auth, handler_options: %{}}
    ]

    opts = [strategy: :one_for_one, name: FragileWater.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
