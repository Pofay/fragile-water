defmodule FragileWater.CryptoSession do
  use GenServer

  def start_link(initial_crypto_state) do
    GenServer.start_link(__MODULE__, initial_crypto_state)
  end

  def update_state(pid, new_crypto_state) do
    GenServer.call(pid, %{update_state: new_crypto_state})
  end

  @impl true
  def init(crypto_state) do
    {:ok, crypto_state}
  end

  @impl true
  def handle_call(%{update_state: new_crypto_state}, _from, current_crypto_state) do
    updated_state = internal_update_state(new_crypto_state, current_crypto_state)
    {:reply, updated_state, updated_state}
  end

  def internal_update_state(new_state, current_state) do
    %{
      current_state
      | send_i: new_state.send_i,
        send_j: new_state.send_j,
        recv_i: new_state.recv_i,
        recv_j: new_state.recv_j
    }
  end
end
