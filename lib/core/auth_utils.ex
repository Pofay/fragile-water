defmodule FragileWater.Core.AuthUtils do
  import Binary, only: [reverse: 1]

  @n <<137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191,
       191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183>>
  @g <<7>>

  @username "pofay"
  @password "pofay"

  def interleave(s) do
    list = Binary.to_list(s)

    t1_hash =
      interleave_t1(list)
      |> Binary.from_list()
      |> sha_hash()
      |> Binary.to_list()

    t2_hash =
      interleave_t2(list)
      |> Binary.from_list()
      |> sha_hash()
      |> Binary.to_list()

    [t1_hash, t2_hash]
    |> Enum.zip()
    |> Enum.map(&Tuple.to_list/1)
    |> List.flatten()
    |> Binary.from_list()
  end

  defp interleave_t1([a, _ | rest]), do: [a | interleave_t1(rest)]
  defp interleave_t1([]), do: []

  defp interleave_t2([_, b | rest]), do: [b | interleave_t2(rest)]
  defp interleave_t2([]), do: []

  defp calculate_private_b(state) do
    private_b = :crypto.strong_rand_bytes(19)
    Map.merge(state, %{private_b: private_b})
  end

  defp calculate_public_b(state) do
    {public_b, _} =
      :crypto.generate_key(
        :srp,
        {:host, [state.verifier, state.g, state.n, :"6"]},
        state.private_b
      )

    Map.merge(state, %{public_b: public_b})
  end

  def account_state(account) do
    salt = :crypto.strong_rand_bytes(32)
    hash = :crypto.hash(:sha, String.upcase(@username) <> ":" <> String.upcase(@password))
    x = reverse(:crypto.hash(:sha, salt <> hash))

    %{n: @n, g: @g}
    |> Map.merge(%{account_name: account})
    |> Map.merge(%{
      verifier: :crypto.mod_pow(@g, x, @n)
    })
    |> Map.merge(%{salt: salt})
  end

  def logon_challenge_state(account) do
    account_state(account)
    |> calculate_private_b
    |> calculate_public_b
  end

  def sha_hash(value) do
    :crypto.hash(:sha, value)
  end
end
