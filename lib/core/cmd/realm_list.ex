defmodule FragileWater.Core.Cmd.RealmList do
  @cmd_realm_list 16

  require Logger

  def generate_payload(<<@cmd_realm_list, _padding::binary>>, state) do
    # From https://wowdev.wiki/CMD_REALM_LIST_Server
    Logger.info("[AuthServer]: REALM_LIST #{inspect(@cmd_realm_list)}")

    # From https://wowdev.wiki/CMD_REALM_LIST_Server#_(2.4.3.8606)
    realm =
      <<1::little-size(8)>> <>
        <<0::size(8)>> <>
        <<0::size(8)>> <>
        "pofay.gg" <>
        <<0>> <>
        "127.0.0.1:8085" <>
        <<0>> <>
        <<200.0::little-float-size(32)>> <>
        <<0::size(8)>> <>
        <<1::size(8)>> <>
        <<0::size(8)>>

    footer = <<0, 0>>
    body = realm <> footer
    # Difference in header size from Vanilla to TBC gives the calculation a -1.
    realms_size = 6 + byte_size(body)
    num_realms = 1

    header =
      <<16::size(8)>> <>
        <<realms_size::little-size(16)>> <>
        <<0::size(32)>> <>
        <<num_realms::little-size(16)>>

    packet = header <> body
    {state, packet}
  end
end
