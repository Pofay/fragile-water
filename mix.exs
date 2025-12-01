defmodule FragileWater.MixProject do
  use Mix.Project

  def project do
    [
      app: :fragile_water,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {FragileWater.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:thousand_island, git: "https://github.com/mtrudel/thousand_island.git"},
      {:telemetry, git: "https://github.com/beam-telemetry/telemetry.git", app: false, manager: :rebar3},
      {:binary, git: "https://github.com/smpoulsen/binary.git"}
    ]
  end
end
