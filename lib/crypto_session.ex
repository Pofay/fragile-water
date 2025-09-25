defmodule FragileWater.CryptoSession do
  use Agent

  def start_link(initial_crypto_state) do
    Agent.start_link(fn -> initial_crypto_state end, name: __MODULE__)
  end

  def update(pid, new_crypto_state) do
    Agent.update(pid, &internal_update(new_crypto_state, &1))
  end

  def get(pid) do
    Agent.get(pid, fn current_crypto_state -> current_crypto_state end)
  end

  def internal_update(new_crypto_state, current_crypto_state) do
    %{
      current_crypto_state
      | send_i: new_crypto_state.send_i,
        send_j: new_crypto_state.send_j,
        recv_i: new_crypto_state.recv_i,
        recv_j: new_crypto_state.recv_j
    }
  end
end
