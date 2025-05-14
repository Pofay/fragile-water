defmodule FragileWater.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {ThousandIsland, port: 3724, handler_module: FragileWater.AuthProxy}
    ]

    opts = [strategy: :one_for_one, name: FragileWater.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp server_opts do
    %{
      port: 8080,
      handler: {FragileWater.Handler, []}
    }
  end
end
