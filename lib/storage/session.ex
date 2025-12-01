defmodule FragileWater.Session do
  use GenServer
  alias FragileWater.Encryption

  def start_link(initial) do
    GenServer.start_link(__MODULE__, initial)
  end

  def encrypt_header(pid, opcode, payload) do
    GenServer.call(pid, {:encrypt_header, opcode, payload})
  end

  def soft_decrypt_header(pid, header) do
    GenServer.call(pid, {:soft_decrypt_header, header})
  end

  def commit_pending_crypto_state(pid) do
    GenServer.call(pid, :commit_pending_crypto_state)
  end

  @impl true
  def init(initial) do
    {:ok, initial}
  end

  @impl true
  def handle_call({:encrypt_header, opcode, payload}, _from, state) do
    size = byte_size(payload) + 2
    header = <<size::big-size(16), opcode::little-size(16)>>
    {encrypted_header, new_state} = Encryption.encrypt_header(header, state)
    {:reply, {:ok, encrypted_header}, new_state}
  end

  @impl true
  def handle_call({:soft_decrypt_header, header}, _from, state) do
    {decrypted_header, crypt_state} = Encryption.decrypt_header(header, state)
    <<size::big-size(16), opcode::little-size(32)>> = decrypted_header
    body_size = size - 4

    if body_size < 0 do
      {:reply, {:error, :invalid_header}, state}
    else
      state_with_pending =
        Map.put(state, :pending_crypto_state, %{
          recv_i: crypt_state.recv_i,
          recv_j: crypt_state.recv_j
        })

      {:reply, {:ok, decrypted_header, body_size, opcode}, state_with_pending}
    end
  end

  @impl true
  def handle_call(:commit_pending_crypto_state, _from, state) do
    case Map.pop(state, :pending_crypto_state) do
      {nil, state} ->
        {:reply, :ok, state}

      {pending_crypto_state, state} ->
        new_state = Map.merge(state, pending_crypto_state)
        {:reply, :ok, new_state}
    end
  end
end
