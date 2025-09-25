# FragileWater

This is my attempt at implementing/reverese-engineering a WoW TBC Server in Elixir. I've mostly followed the implementations from these sources with some changes to handle TBC specific packet payloads:

- [Thistle Tea](https://github.com/pikdum/thistle_tea)
- [Shadowburn Project](https://gitlab.com/shadowburn/shadowburn)
- [Gtker's Blog](https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/)
- [WowDev](https://wowdev.wiki/Login_Packet)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `fragile_water` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:fragile_water, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/fragile_water>.

