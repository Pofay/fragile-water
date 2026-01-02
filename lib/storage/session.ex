defmodule FragileWater.Session do
  use GenServer
  alias FragileWater.Encryption

  def start_link(initial) do
    GenServer.start_link(__MODULE__, initial)
  end

  def encrypt_header(pid, opcode, payload) do
    GenServer.call(pid, {:encrypt_header, opcode, payload})
  end

  def enqueue_packets(pid, header) do
    GenServer.call(pid, {:enqueue_packets, header})
  end

  def commit_enqueued_packets(pid) do
    GenServer.call(pid, :commit_enqueued_packets)
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
  def handle_call({:enqueue_packets, header}, _from, state) do
    {decrypted_header, crypt_state} = Encryption.decrypt_header(header, state)
    <<size::big-size(16), opcode::little-size(32)>> = decrypted_header
    body_size = size - 4

    if body_size < 0 do
      {:reply, {:error, :invalid_header}, state}
    else
      state_with_pending =
        Map.put(state, :enqueued_packets, %{
          recv_i: crypt_state.recv_i,
          recv_j: crypt_state.recv_j
        })

      {:reply, {:ok, body_size, opcode}, state_with_pending}
    end
  end

  @impl true
  def handle_call(:commit_enqueued_packets, _from, state) do
    case Map.pop(state, :enqueued_packets) do
      {nil, state} ->
        {:reply, :ok, state}

      {enqueued_packets, state} ->
        new_state = Map.merge(state, enqueued_packets)
        {:reply, :ok, new_state}
    end
  end
end
