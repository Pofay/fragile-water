Looks like I get the issue with not being able to create a character in my laptop.

Also weird is I don't get these messages:

- CMSG_PING
- CMSG_REALM_SPLIT


For starters, to check what version of Elixir and Erlang I'm using to first diagnose the issue:

Laptop Installation:

- Erlang/OTP 27 [erts-15.2.7.4] [source] [64-bit] [smp:20:20] [ds:20:20:10] [async-threads:1] [jit:ns]
- Elixir 1.18.2 (compiled with Erlang/OTP 27)

PC Installation:

-
- 

TODO:

- Verify if current state of the code works in PC.
- Lock the version of Elixir in `mix.exs` from `1.18` -> `1.18.<PC_VERSION>`
- Check if installation of Jason, Credo and bunt caused this.
