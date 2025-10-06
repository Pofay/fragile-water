defmodule FragileWater.Encryption do
  import Bitwise, only: [bxor: 2]
  require Logger

  def build_packet(opcode, payload, crypt) do
    size = byte_size(payload) + 2
    header = <<size::big-size(16), opcode::little-size(16)>>

    Logger.info(
      "[GameServer] Encrypting header: #{inspect(header)} with crypt: #{inspect(crypt)}"
    )

    {encrypted_header, new_crypt} = encrypt_header(header, crypt)

    Logger.info(
      "[GameServer] Encrypted header: #{inspect(encrypted_header)} with new crypt: #{inspect(new_crypt)}"
    )

    {encrypted_header <> payload, new_crypt}
  end

  def create_tbc_key(session) do
    s_key =
      <<0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2,
        0xAA>>

    :crypto.mac(:hmac, :sha, s_key, session)
  end

  def encrypt_header(header, state) do
    acc = {<<>>, %{send_i: state.send_i, send_j: state.send_j}}

    {header, crypt_state} =
      Enum.reduce(:binary.bin_to_list(header), acc, fn byte, {header, crypt} ->
        send_i = rem(crypt.send_i, byte_size(state.key))
        x = bxor(byte, :binary.at(state.key, send_i)) + crypt.send_j
        <<truncated_x>> = <<x::little-size(8)>>
        {header <> <<truncated_x>>, %{send_i: send_i + 1, send_j: truncated_x}}
      end)

    {header, Map.merge(state, crypt_state)}
  end

  def decrypt_header(header, state) do
    acc = {<<>>, %{recv_i: state.recv_i, recv_j: state.recv_j}}

    {header, crypt_state} =
      Enum.reduce(
        :binary.bin_to_list(header),
        acc,
        fn byte, {header, crypt} ->
          recv_i = rem(crypt.recv_i, byte_size(state.key))
          x = bxor(byte - crypt.recv_j, :binary.at(state.key, recv_i))
          <<truncated_x>> = <<x::little-size(8)>>
          {header <> <<truncated_x>>, %{recv_i: recv_i + 1, recv_j: byte}}
        end
      )

    {header, Map.merge(state, crypt_state)}
  end
end
