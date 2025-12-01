defmodule FragileWater.WorldConnection do
  use GenServer

  import Bitwise, only: [bxor: 2]

  def start_link(initial) do
    GenServer.start_link(__MODULE__, initial)
  end

  @doc """
  Encrypt a 4-byte server header.
  
  The server header format is:
  - 2 bytes: size (big-endian), includes opcode (payload size + 2)
  - 2 bytes: opcode (little-endian)
  
  Returns {:ok, encrypted_header}.
  """
  def encrypt_header(pid, opcode, payload) do
    GenServer.call(pid, {:encrypt_header, opcode, payload})
  end

  @doc """
  Peek at a 6-byte client header without committing crypto state.
  Returns {:ok, decrypted_header, body_size, opcode}.
  
  The client header format is:
  - 2 bytes: size (big-endian)
  - 4 bytes: opcode (little-endian)
  
  body_size is calculated as size - 4 (excludes opcode bytes).
  Use this to check if we have enough data for a complete packet.
  """
  def peek_header(pid, header) do
    GenServer.call(pid, {:peek_header, header})
  end

  @doc """
  Commit the crypto state after successfully processing a complete packet.
  This advances recv_i/recv_j by the header size (6 bytes).
  """
  def commit_header_crypto(pid) do
    GenServer.call(pid, :commit_header_crypto)
  end

  @impl true
  def init(initial) do
    {:ok, initial}
  end

  @impl true
  def handle_call({:encrypt_header, opcode, payload}, _from, state) do
    size = byte_size(payload) + 2
    header = <<size::big-size(16), opcode::little-size(16)>>
    {encrypted_header, new_state} = internal_encrypt_header(header, state)
    {:reply, {:ok, encrypted_header}, new_state}
  end

  @impl true
  def handle_call({:peek_header, header}, _from, state) do
    {decrypted_header, crypt_state} = internal_decrypt_header_with_crypt(header, state)
    <<size::big-size(16), opcode::little-size(32)>> = decrypted_header
    body_size = size - 4

    # Validate that body_size is non-negative (size must be at least 4 for valid packet)
    if body_size < 0 do
      {:reply, {:error, :invalid_header}, state}
    else
      # Store only the recv_i/recv_j changes to be committed later
      state_with_pending = Map.put(state, :pending_recv_crypt, crypt_state)

      {:reply, {:ok, decrypted_header, body_size, opcode}, state_with_pending}
    end
  end

  @impl true
  def handle_call(:commit_header_crypto, _from, state) do
    case Map.pop(state, :pending_recv_crypt) do
      {nil, state} ->
        # No pending state, nothing to commit
        {:reply, :ok, state}

      {pending_crypt, state} ->
        # Commit the pending recv_i/recv_j changes
        new_state = Map.merge(state, pending_crypt)
        {:reply, :ok, new_state}
    end
  end

  defp internal_encrypt_header(header, state) do
    initial_acc = {<<>>, %{send_i: state.send_i, send_j: state.send_j}}

    {header, crypt_state} =
      Enum.reduce(
        :binary.bin_to_list(header),
        initial_acc,
        fn byte, {header, crypt} ->
          send_i = rem(crypt.send_i, byte_size(state.key))
          x = bxor(byte, :binary.at(state.key, send_i)) + crypt.send_j
          <<truncated_x>> = <<x::little-size(8)>>
          {header <> <<truncated_x>>, %{send_i: send_i + 1, send_j: truncated_x}}
        end
      )

    {header, Map.merge(state, crypt_state)}
  end

  # Returns {decrypted_header, crypt_state} where crypt_state is just %{recv_i, recv_j}
  defp internal_decrypt_header_with_crypt(header, state) do
    initial_acc = {<<>>, %{recv_i: state.recv_i, recv_j: state.recv_j}}

    Enum.reduce(
      :binary.bin_to_list(header),
      initial_acc,
      fn byte, {header, crypt} ->
        recv_i = rem(crypt.recv_i, byte_size(state.key))
        x = bxor(byte - crypt.recv_j, :binary.at(state.key, recv_i))
        <<truncated_x>> = <<x::little-size(8)>>
        {header <> <<truncated_x>>, %{recv_i: recv_i + 1, recv_j: byte}}
      end
    )
  end
end
