const listener = Deno.listen({ port: 3724 });
console.log("Deno Auth Server listening on 0.0.0.0:3724");

const CMD_AUTH_LOGON_CHALLENGE = 0x00;
const CMD_AUTH_LOGON_PROOF = 0x01;

const username = "pofay";
const password = "pofay";
const N = BigInt(
  "0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
);
const G = 7n;
const k = 3n;

for await (const conn of listener) {
  const state = createAccountState();

  handleConn(conn, state);
}

async function handleConn(conn: Deno.Conn, state: AccountState) {
  let mutableState = state;

  for await (const chunk of conn.readable) {
    const cmd = chunk[0];

    switch (cmd) {
      case CMD_AUTH_LOGON_CHALLENGE:
        mutableState = await handleLogonChallenge(chunk, mutableState);
        await conn.write(generatePacket(mutableState));
        break;
      case CMD_AUTH_LOGON_PROOF:
        console.table(conn);
        console.table(mutableState);
        console.warn(`Unsupported opcode for now.`);
        break;
      default:
        console.warn(`Unknown opcode: 0x${cmd.toString(16).padStart(2, "0")}`);
    }
  }
}

async function handleLogonChallenge(
  chunk: Uint8Array<ArrayBuffer>,
  state: AccountState,
) {
  const packet = parseAuthLogonChallenge(chunk);

  console.info(`[AuthServer]: AUTH_LOGON_CHALLENGE for: ${packet.accountName}`);

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const hash = await generateSRPHash(username, password);
  const x = await generateX(salt, hash);
  const verifier = modpow(G, x, N);
  const privateB = bytesToBigInt(crypto.getRandomValues(new Uint8Array(19)));
  const publicB = generatePublicB(verifier, privateB);

  const updatedState = state;
  updatedState.accountName = packet.accountName;
  updatedState.salt = salt;
  updatedState.verifier = verifier;
  updatedState.privateB = privateB;
  updatedState.publicB = publicB;

  return updatedState;
}

function generatePacket(state: AccountState) {
  const unk3 = crypto.getRandomValues(new Uint8Array(16));
  const parts = [
    new Uint8Array([0, 0, 0]),
    bigIntToBytes(state.publicB, 32).reverse(),
    new Uint8Array([1]),
    new Uint8Array([Number(G)]),
    new Uint8Array([32]),
    bigIntToBytes(N, 32).reverse(),
    state.salt,
    unk3,
    new Uint8Array([0]),
  ];
  const total = parts.reduce((n, a) => n + a.length, 0);
  const packet = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    packet.set(part, offset);
    offset += part.length;
  }
  return packet;
}

function parseAuthLogonChallenge(chunk: Uint8Array<ArrayBuffer>) {
  const view = new DataView(chunk.buffer);

  let offset = 0;

  const cmd = view.getUint8(offset);
  offset += 1;
  const protocolVersion = view.getUint8(offset);
  offset += 1;
  const size = view.getUint16(offset, true);
  offset += 2;
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

function createAccountState() {
  return {
    accountName: "",
    salt: Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0]),
    verifier: BigInt(0),
    publicB: BigInt(0),
    privateB: BigInt(0),
  };
}

interface AccountState {
  accountName: string;
  salt: Uint8Array;
  verifier: bigint;
  publicB: bigint;
  privateB: bigint;
}

async function generateSRPHash(username: string, password: string) {
  const encoder = new TextEncoder();

  const hashString = await crypto.subtle.digest(
    "SHA-1",
    encoder.encode(username.toUpperCase() + ":" + password.toUpperCase()),
  );

  return new Uint8Array(hashString);
}

async function generateX(salt: Uint8Array, hash: Uint8Array) {
  const concat = (a: Uint8Array, b: Uint8Array): ArrayBuffer => {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result.buffer;
  };

  const x = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-1",
      concat(salt, hash),
    ),
  );

  return bytesToBigInt(x.reverse());
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
}

function generatePublicB(passwordVerifier: bigint, serverPrivateKey: bigint) {
  const interim = k * passwordVerifier + modpow(G, serverPrivateKey, N);

  return interim % N;
}

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

export function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    result[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return result;
}
