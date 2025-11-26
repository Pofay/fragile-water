Looks like I get the issue with not being able to create a character in my laptop.

In addition, in my laptop I don't receive these messages:

- `CMSG_PING`
- `CMSG_REALM_SPLIT`

For starters, to check what version of Elixir and Erlang I'm using to first diagnose the issue.

# Laptop Installation:

- Erlang/OTP 27 [erts-15.2.7.4] [source] [64-bit] [smp:20:20] [ds:20:20:10] [async-threads:1] [jit:ns]
- Elixir 1.18.2 (compiled with Erlang/OTP 27)
- WoW TBC Client from Stormforge

# PC Installation:
-
- 
-

# TODO:

- Verify if current state of the code works in PC. Delete build, deps, and elixir_ls folders and reinstall deps, rebuild and run.
- Lock the version of Elixir in `mix.exs` from `1.18` -> `1.18.<PC_VERSION>`
- Check if installation of Jason, Credo and bunt caused this.
- Check if WoW Client used is downloaded from the same source.


Additionally:

- Maybe setting up CMangos for the client fix this issue.


Found out that in my laptop, I log-in twice as shown why I have two crypto running. 

The first one shows a succesful login and then a follow up unimplemented opcode that doesn't map to the Opcodes documentation.


```

20:36:24.526 [info] [GameServer] Crypto PID: #PID<0.796.0>

20:36:28.204 [error] [GameServer] Unimplemented opcode: 0xF232010

20:36:28.241 [info] [GameServer] Crypto PID: #PID<0.798.0>
```

The first one shows a succesful login and then a follow up unimplemented opcode that doesn't map to the Opcodes documentation.

After showing the opcode it tries to login again hence why there's two processes running.
