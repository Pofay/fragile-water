defmodule FragileWater.Core.Cmd.AuthLogonProof do
  alias FragileWater.Core.AuthUtils
  alias FragileWater.SessionKeyStorage

  import Binary, only: [reverse: 1]

  require Logger

  @cmd_auth_logon_proof 1
  @n <<137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191,
       191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183>>
  @g <<7>>

  def generate_payload(
        <<@cmd_auth_logon_proof, client_public_key::little-bytes-size(32),
          client_proof::little-bytes-size(20), _crc_hash::little-bytes-size(20),
          _number_of_keys::little-size(8), _security_flags::little-size(8)>>,
        state
      ) do
    Logger.info("[AuthServer]: AUTH_LOGIN_PROOF for: #{state.account_name}")

    public_a = reverse(client_public_key)
    scrambler = :crypto.hash(:sha, reverse(public_a) <> reverse(state.public_b))

    compute_key =
      :crypto.compute_key(
        :srp,
        public_a,
        {state.public_b, state.private_b},
        {:host, [state.verifier, @n, :"6", reverse(scrambler)]}
      )

    s = reverse(compute_key)

    session = AuthUtils.interleave(s)

    Logger.info("[AuthServer]: Session key size generated: #{inspect(byte_size(session))}")

    mod_hash = :crypto.hash(:sha, reverse(@n))
    generator_hash = :crypto.hash(:sha, @g)

    t3 = :crypto.exor(mod_hash, generator_hash)
    t4 = :crypto.hash(:sha, state.account_name)

    m =
      :crypto.hash(
        :sha,
        t3 <> t4 <> state.salt <> reverse(public_a) <> reverse(state.public_b) <> session
      )

    Logger.info("[AuthServer]: Verifying client proof for #{state.account_name}")

    if m == client_proof do
      Logger.info("[AuthServer]: Client proof matched for #{state.account_name}")

      server_proof = :crypto.hash(:sha, reverse(public_a) <> client_proof <> session)

      state =
        Map.merge(state, %{public_a: public_a, session: session, server_proof: server_proof})

      # From https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Server
      packet =
        IO.iodata_to_binary([
          <<1, 0>>,
          state.server_proof,
          <<0, 0, 128, 0>>,
          <<0, 0, 0, 0>>,
          <<0, 0>>
        ])

      Logger.info("Packet: #{inspect(packet)}")

      {:continue, state, packet}
    else
      Logger.error("Client proof does not match!")
      Logger.info("public_a: #{inspect(public_a)}")
      Logger.info("client_proof: #{inspect(client_proof)}")
      Logger.info("m: #{inspect(m)}")
      {:close, state, <<0, 0, 5>>}
    end
  end

  def post_handle(state) do
    SessionKeyStorage.put(state.account_name, state.session)
    state
  end
end
