defmodule FragileWater.WorldConnectionTest do
  use ExUnit.Case

  import Bitwise, only: [bxor: 2]

  alias FragileWater.WorldConnection

  # Create a test encryption key (same algorithm as Encryption.create_tbc_key)
  defp create_test_key do
    session = :crypto.strong_rand_bytes(40)
    s_key = <<0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2, 0xAA>>
    :crypto.mac(:hmac, :sha, s_key, session)
  end

  defp create_crypto_state do
    %{
      key: create_test_key(),
      send_i: 0,
      send_j: 0,
      recv_i: 0,
      recv_j: 0
    }
  end

  # Create an encrypted client header (6 bytes: 2 size + 4 opcode)
  # This simulates what a client would send
  defp encrypt_client_header(opcode, body_size, state) do
    # Client header: size (includes 4-byte opcode) + opcode
    size = body_size + 4
    header = <<size::big-size(16), opcode::little-size(32)>>
    
    # Encrypt using the same algorithm as internal_encrypt_header but for send direction
    initial_acc = {<<>>, %{send_i: state.send_i, send_j: state.send_j}}

    {encrypted_header, crypt_state} =
      Enum.reduce(
        :binary.bin_to_list(header),
        initial_acc,
        fn byte, {header_acc, crypt} ->
          send_i = rem(crypt.send_i, byte_size(state.key))
          x = bxor(byte, :binary.at(state.key, send_i)) + crypt.send_j
          <<truncated_x>> = <<x::little-size(8)>>
          {header_acc <> <<truncated_x>>, %{send_i: send_i + 1, send_j: truncated_x}}
        end
      )

    {encrypted_header, Map.merge(state, crypt_state)}
  end

  describe "peek_header/2" do
    test "decrypts client header and returns body size without committing state" do
      state = create_crypto_state()
      {:ok, receiver} = WorldConnection.start_link(state)

      # Create an encrypted client header
      opcode = 0x037
      body_size = 10
      {encrypted_header, _} = encrypt_client_header(opcode, body_size, state)

      # Peek at the header
      {:ok, decrypted, decoded_body_size, decoded_opcode} = WorldConnection.peek_header(receiver, encrypted_header)

      # Verify the decoded values
      assert decoded_body_size == body_size
      assert decoded_opcode == opcode
      assert byte_size(decrypted) == 6
    end

    test "peek twice returns same result because state is not committed" do
      state = create_crypto_state()
      {:ok, receiver} = WorldConnection.start_link(state)

      opcode = 0x037
      body_size = 10
      {encrypted_header, _} = encrypt_client_header(opcode, body_size, state)

      # Peek twice
      {:ok, d1, s1, o1} = WorldConnection.peek_header(receiver, encrypted_header)
      {:ok, d2, s2, o2} = WorldConnection.peek_header(receiver, encrypted_header)

      # Results should be identical
      assert d1 == d2
      assert s1 == s2
      assert o1 == o2
    end

    test "peek followed by commit advances crypto state correctly" do
      state = create_crypto_state()
      {:ok, receiver} = WorldConnection.start_link(state)

      # Create two encrypted client headers in sequence
      opcode1 = 0x037
      body_size1 = 10
      {encrypted1, state_after_first} = encrypt_client_header(opcode1, body_size1, state)

      opcode2 = 0x038
      body_size2 = 20
      {encrypted2, _} = encrypt_client_header(opcode2, body_size2, state_after_first)

      # Peek and commit first header
      {:ok, _d1, s1, o1} = WorldConnection.peek_header(receiver, encrypted1)
      assert o1 == opcode1
      assert s1 == body_size1
      :ok = WorldConnection.commit_header_crypto(receiver)

      # Now peek second header - should decode correctly because state was committed
      {:ok, _d2, s2, o2} = WorldConnection.peek_header(receiver, encrypted2)
      assert o2 == opcode2
      assert s2 == body_size2
    end

    test "peek without commit causes wrong decryption for next packet" do
      state = create_crypto_state()
      {:ok, receiver} = WorldConnection.start_link(state)

      # Create two encrypted client headers in sequence
      opcode1 = 0x037
      body_size1 = 10
      {encrypted1, state_after_first} = encrypt_client_header(opcode1, body_size1, state)

      opcode2 = 0x038
      body_size2 = 20
      {encrypted2, _} = encrypt_client_header(opcode2, body_size2, state_after_first)

      # Peek first header but DON'T commit
      {:ok, _d1, s1, o1} = WorldConnection.peek_header(receiver, encrypted1)
      assert o1 == opcode1
      assert s1 == body_size1
      # No commit here!

      # Try to peek second header - will fail because recv state wasn't advanced
      {:ok, _d2, s2, o2} = WorldConnection.peek_header(receiver, encrypted2)
      # The opcode and size will be garbage because we decrypted with wrong state
      assert o2 != opcode2 or s2 != body_size2
    end
  end

  describe "commit_header_crypto/1" do
    test "commit without peek does nothing harmful" do
      {:ok, pid} = WorldConnection.start_link(create_crypto_state())

      # Commit without peeking should succeed without error
      assert :ok == WorldConnection.commit_header_crypto(pid)
    end

    test "double commit is safe" do
      state = create_crypto_state()
      {:ok, receiver} = WorldConnection.start_link(state)

      opcode = 0x037
      body_size = 10
      {encrypted_header, _} = encrypt_client_header(opcode, body_size, state)

      # Peek and commit
      {:ok, _, _, _} = WorldConnection.peek_header(receiver, encrypted_header)
      :ok = WorldConnection.commit_header_crypto(receiver)

      # Second commit should be safe (no-op since pending state was already applied)
      :ok = WorldConnection.commit_header_crypto(receiver)
    end
  end

  describe "encrypt_header/3" do
    test "encrypts server header correctly (4 bytes)" do
      {:ok, pid} = WorldConnection.start_link(create_crypto_state())

      opcode = 0x1EE
      payload = <<0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>

      {:ok, encrypted} = WorldConnection.encrypt_header(pid, opcode, payload)

      # Server header should be 4 bytes (2 size + 2 opcode for TBC)
      assert byte_size(encrypted) == 4
    end
  end
end
