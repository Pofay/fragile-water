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
- There is some preliminary work with the client when installing `CMangos`. See if the files generated actually fixes the issue of not being able to create a character (multi process after login will still persist with this.)

- **Reference pikdum's fix during [June 20-21](https://pikdum.dev/posts/thistle-tea/) for [Shadowburn's implementation on handling partial packet](https://gitlab.com/shadowburn/shadowburn/-/blob/master/apps/serverd/lib/session.ex?ref_type=heads#L433) sends. I think this will resolve the issue**.

- [Handling the accumulation of packets](https://github.com/pikdum/thistle_tea/commit/e53ec3663d4b933c6ca0331900b0083c79a9770e)
- [Handling login race condition](https://github.com/pikdum/thistle_tea/commit/1e4182d03a85857156832aebe7e763554f25b0fa)

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

# Update

This also happens when using the `thistle_tea` server implementation (with some updates to handle tbc specific server proof generation, realm list and character creation data)

```
11:03:33.804 [info] [GameServer] CMSG_AUTH_SESSION: username: PIKDUM, build: 8606, server_id: 0

11:03:33.804 [info] [GameServer] Authentication successful: PIKDUM

11:03:33.807 [info] [GameServer] Created new session with crypto PID: #PID<0.859.0>

11:03:34.319 [info] [GameServer] CMSG_CHAR_ENUM

11:03:34.339 [info] [AuthServer] CMD_REALM_LIST

11:03:38.168 [error] [GameServer] Unimplemented opcode: 0xDBCE7CAC

11:03:38.186 [info] [GameServer] SMSG_AUTH_CHALLENGE

11:03:38.204 [info] [GameServer] CMSG_AUTH_SESSION: username: PIKDUM, build: 8606, server_id: 0 

11:03:38.204 [info] [GameServer] Authentication successful: PIKDUM

11:03:38.204 [info] [GameServer] Created new session with crypto PID: #PID<0.861.0>

11:03:38.219 [info] [GameServer] CMSG_CHAR_ENUM

11:04:08.269 [error] [GameServer] Unimplemented opcode: 0xDBCE7D47
```
