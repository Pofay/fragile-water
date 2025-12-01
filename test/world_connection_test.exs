defmodule FragileWater.WorldConnectionTest do
  use ExUnit.Case

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

  describe "peek_header/2" do
    test "decrypts header and returns body size without committing state" do
      {:ok, pid} = WorldConnection.start_link(create_crypto_state())

      # Create a test encrypted header
      # For this test, we'll use encrypt_header to create a valid encrypted header
      opcode = 0x037
      payload = <<1, 2, 3, 4>>
      {:ok, encrypted_header} = WorldConnection.encrypt_header(pid, opcode, payload)

      # Reset the recv state by creating a new connection
      {:ok, pid2} = WorldConnection.start_link(create_crypto_state())

      # First, encrypt a header to advance send state, then peek at it
      {:ok, _} = WorldConnection.encrypt_header(pid2, opcode, payload)

      # Now we need to test peek_header - but we need matching encrypted data
      # Let's use a simpler approach: peek twice and verify state doesn't change

      # For a proper test, we'd need to encrypt with one connection and decrypt with another
      # using the same initial state

      # Create two identical connections
      state = create_crypto_state()
      {:ok, sender} = WorldConnection.start_link(state)
      {:ok, receiver} = WorldConnection.start_link(state)

      # Encrypt a header
      {:ok, encrypted} = WorldConnection.encrypt_header(sender, opcode, payload)

      # Peek at the header
      {:ok, _decrypted, body_size, decoded_opcode} = WorldConnection.peek_header(receiver, encrypted)

      # Verify the decoded values
      assert body_size == byte_size(payload)
      assert decoded_opcode == opcode

      # Peek again - should get the same result because state wasn't committed
      {:ok, _decrypted2, body_size2, decoded_opcode2} = WorldConnection.peek_header(receiver, encrypted)

      assert body_size2 == body_size
      assert decoded_opcode2 == decoded_opcode
    end

    test "peek followed by commit advances crypto state" do
      state = create_crypto_state()
      {:ok, sender} = WorldConnection.start_link(state)
      {:ok, receiver} = WorldConnection.start_link(state)

      # Encrypt two headers
      opcode1 = 0x037
      payload1 = <<1, 2, 3, 4>>
      {:ok, encrypted1} = WorldConnection.encrypt_header(sender, opcode1, payload1)

      opcode2 = 0x038
      payload2 = <<5, 6, 7, 8>>
      {:ok, encrypted2} = WorldConnection.encrypt_header(sender, opcode2, payload2)

      # Peek and commit first header
      {:ok, _decrypted1, body_size1, decoded_opcode1} = WorldConnection.peek_header(receiver, encrypted1)
      assert decoded_opcode1 == opcode1
      assert body_size1 == byte_size(payload1)
      :ok = WorldConnection.commit_header_crypto(receiver)

      # Now peek second header - should decode correctly because state was committed
      {:ok, _decrypted2, body_size2, decoded_opcode2} = WorldConnection.peek_header(receiver, encrypted2)
      assert decoded_opcode2 == opcode2
      assert body_size2 == byte_size(payload2)
    end

    test "multiple peeks without commit return same result" do
      state = create_crypto_state()
      {:ok, sender} = WorldConnection.start_link(state)
      {:ok, receiver} = WorldConnection.start_link(state)

      # Encrypt a header
      opcode = 0x037
      payload = <<1, 2, 3, 4>>
      {:ok, encrypted} = WorldConnection.encrypt_header(sender, opcode, payload)

      # Peek multiple times
      {:ok, d1, s1, o1} = WorldConnection.peek_header(receiver, encrypted)
      {:ok, d2, s2, o2} = WorldConnection.peek_header(receiver, encrypted)
      {:ok, d3, s3, o3} = WorldConnection.peek_header(receiver, encrypted)

      # All should return the same result
      assert d1 == d2
      assert d2 == d3
      assert s1 == s2
      assert s2 == s3
      assert o1 == o2
      assert o2 == o3
    end
  end

  describe "commit_header_crypto/1" do
    test "commit without peek does nothing" do
      {:ok, pid} = WorldConnection.start_link(create_crypto_state())

      # Commit without peeking should succeed without error
      assert :ok == WorldConnection.commit_header_crypto(pid)
    end
  end

  describe "encrypt_header/3" do
    test "encrypts header correctly" do
      {:ok, pid} = WorldConnection.start_link(create_crypto_state())

      opcode = 0x1EE
      payload = <<0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>

      {:ok, encrypted} = WorldConnection.encrypt_header(pid, opcode, payload)

      # Header should be 4 bytes (2 size + 2 opcode for TBC)
      assert byte_size(encrypted) == 4
    end
  end
end
