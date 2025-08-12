defmodule FragileWater.Auth do
  @moduledoc """
  Based on implementation from pikdum/thistle_tea
  https://github.com/pikdum/thistle_tea/commit/33a9756eeafc5d24bd903ab9f80b446e72cce428#diff-04ab6d976a6cff089eb06be2022d35e31e31e37e45c3e97f7816ee37521c70cf
  """
  use ThousandIsland.Handler
  require Logger

  import Binary, only: [reverse: 1]

  @cmd_auth_logon_challenge 0
  @cmd_auth_logon_proof 1

  @n <<137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191,
       191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183>>
  @g <<7>>

  @username "pofay"
  @password "pofay"

  @impl ThousandIsland.Handler
  def handle_data(
        <<@cmd_auth_logon_challenge, _error::little-size(8), _size::little-size(16),
          _game::bytes-little-size(4), _v1::little-size(8), _v2::little-size(8),
          _v3::little-size(8), _build::little-size(16), _platform::bytes-little-size(4),
          _os::bytes-size(4), _locale::bytes-size(4), _utc_offset::little-size(32),
          _ip::little-size(32), username_length::unsigned-little-size(8),
          username::bytes-little-size(username_length)>>,
        socket,
        _state
      ) do
    Logger.info("Handling logon challenge")

    salt =
      <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0>>

    hash = :crypto.hash(:sha, String.upcase(@username) <> ":" <> String.upcase(@password))
    x = reverse(:crypto.hash(:sha, salt <> hash))
    verifier = :crypto.mod_pow(@g, x, @n)

    private_b = :crypto.strong_rand_bytes(19)
    {public_b, _} = :crypto.generate_key(:srp, {:host, [verifier, @g, @n, :"6"]}, private_b)

    unk3 = :crypto.strong_rand_bytes(16)

    response =
      <<0, 0, 0>> <>
        reverse(public_b) <> <<1, @g, 32>> <> reverse(@n) <> salt <> unk3 <> <<0>>

    IO.inspect(response, label: "Response", limit: :infinity)

    ThousandIsland.Socket.send(
      socket,
      response
    )

    {:continue,
     %{
       salt: salt,
       verifier: verifier,
       private_b: private_b,
       public_b: public_b,
       username: username
     }}
  end

  @impl ThousandIsland.Handler
  def handle_data(
        <<@cmd_auth_logon_proof, public_a::little-bytes-size(32),
          client_proof::little-bytes-size(20), _crc_hash::little-bytes-size(20),
          _number_of_keys::little-size(8), _security_flags::little-size(8)>>,
        socket,
        state
      ) do
    Logger.info("LOGON PROOF")
    Logger.info("state: #{inspect(state)}")

    public_a_reversed = reverse(public_a)
    scrambler = :crypto.hash(:sha, public_a <> reverse(state.public_b))

    compute_key =
      :crypto.compute_key(
        :srp,
        public_a_reversed,
        {state.public_b, state.private_b},
        {:host, [state.verifier, @n, :"6", reverse(scrambler)]}
      )

    s = reverse(compute_key)

    session = interleave(s)

    mod_hash = :crypto.hash(:sha, reverse(@n))
    generator_hash = :crypto.hash(:sha, @g)

    t3 = :crypto.exor(mod_hash, generator_hash)
    t4 = :crypto.hash(:sha, state.username)

    m =
      :crypto.hash(:sha, t3 <> t4 <> state.salt <> public_a <> reverse(state.public_b) <> session)

    if m == client_proof do
      Logger.info("Client proof matches!")
    else
      Logger.error("Client proof does not match!")
      Logger.info("public_a: #{inspect(public_a)}")
      Logger.info("client_proof: #{inspect(client_proof)}")
      Logger.info("m: #{inspect(m)}")
    end

    ThousandIsland.Socket.send(socket, <<0, 0, 5>>)
    {:close, state}
  end

  @impl ThousandIsland.Handler
  def handle_data(data, socket, state) do
    IO.inspect("UNHANDLED")
    <<msg::binary-size(1), _rest::binary>> = data
    IO.inspect("Actual Message: #{msg}", base: :binary)
    IO.inspect("Actual Data: #{data}", base: :binary)
    ThousandIsland.Socket.send(socket, data)
    {:continue, state}
  end

  defp interleave(s) do
    list = Binary.to_list(s)

    t1 = Binary.from_list(interleave_t1(list))
    t2 = Binary.from_list(interleave_t2(list))

    t1_hash = Binary.to_list(:crypto.hash(:sha, t1))
    t2_hash = Binary.to_list(:crypto.hash(:sha, t2))

    Enum.zip([t1_hash, t2_hash])
    |> Enum.map(&Tuple.to_list/1)
    |> List.flatten()
    |> Binary.from_list()
  end

  defp interleave_t1([a, _ | rest]), do: [a | interleave_t1(rest)]
  defp interleave_t1([]), do: []

  defp interleave_t2([_, b | rest]), do: [b | interleave_t2(rest)]
  defp interleave_t2([]), do: []
end
