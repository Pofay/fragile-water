const listener = Deno.listen({ port: 3724 });
console.log("Deno Auth Server listening on 0.0.0.0:3724");

const CMD_AUTH_LOGON_CHALLENGE = 0x00;

for await (const conn of listener) {
  handleConn(conn);
}

async function handleConn(conn: Deno.Conn) {
  for await (const chunk of conn.readable) {
    const cmd = chunk[0];

    switch (cmd) {
      case CMD_AUTH_LOGON_CHALLENGE:
        handleLogonChallenge(chunk);
        break;
      default:
        console.warn(`Unknown opcode: 0x${cmd.toString(16).padStart(2, "0")}`);
    }
  }
}

async function handleLogonChallenge(chunk: Uint8Array<ArrayBuffer>) {
  const packet = parseAuthLogonChallenge(chunk);

  console.table(packet);
}

function parseAuthLogonChallenge(chunk: Uint8Array<ArrayBuffer>) {
  const view = new DataView(chunk.buffer);

  let offset = 0;

  const cmd = view.getUint8(offset);
  offset += 1;
  const protocolVersion = view.getUint8(offset);
  offset += 1;
  const size = view.getUint16(offset, true);
  offset += 2; // little-endian
  const gameName = chunk.slice(offset, offset + 4);
  offset += 4;
  const version = chunk.slice(offset, offset + 3);
  offset += 3;
  const build = view.getUint16(offset, true);
  offset += 2;
  const platform = chunk.slice(offset, offset + 4);
  offset += 4;
  const os = chunk.slice(offset, offset + 4);
  offset += 4;
  const locale = chunk.slice(offset, offset + 4);
  offset += 4;
  const worldRegionBias = view.getUint32(offset, true);
  offset += 4;
  const ip = view.getUint32(offset, true);
  offset += 4;
  const accountNameLen = view.getUint8(offset);
  offset += 1;
  const accountName = new TextDecoder().decode(
    chunk.slice(offset, offset + accountNameLen),
  );

  return {
    cmd,
    protocolVersion,
    size,
    gameName,
    version,
    build,
    platform,
    os,
    locale,
    worldRegionBias,
    ip,
    accountName,
  };
}
