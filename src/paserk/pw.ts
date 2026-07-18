import { blake2b } from '@noble/hashes/blake2b';
import { argon2id } from '@noble/hashes/argon2';
import { xchacha20 } from '@noble/ciphers/chacha';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { randomBytes } from '../keys/generate.js';
import { LocalKey, SecretKey } from '../keys/types.js';
import { PaserkError } from '../errors.js';

const LOCAL_H = 'k4.local-pw.';
const SECRET_H = 'k4.secret-pw.';

export interface PwOpts {
  /** libsodium memlimit in BYTES (default 64 MiB). */
  memlimit?: number;
  /** libsodium opslimit / Argon2 iterations (default 2). */
  opslimit?: number;
  /** Argon2 parallelism degree (default 1). */
  parallelism?: number;
}

function be64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}
function be32(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}
function readBe64(b: Uint8Array): number {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(b[i]!);
  return Number(v);
}
function readBe32(b: Uint8Array, off: number): number {
  return ((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0;
}
function toBytes(x: string | Uint8Array): Uint8Array {
  return typeof x === 'string' ? utf8(x) : x;
}

// Argon2id memory param `m` is KiB; libsodium memlimit is bytes.
function derive(pw: Uint8Array, salt: Uint8Array, mem: number, time: number, para: number) {
  const k = argon2id(pw, salt, { t: time, m: Math.floor(mem / 1024), p: para, dkLen: 32 });
  return {
    Ek: blake2b(concat(Uint8Array.of(0xff), k), { dkLen: 32 }),
    Ak: blake2b(concat(Uint8Array.of(0xfe), k), { dkLen: 32 }),
  };
}

export function _wrapPw(
  ptk: Uint8Array,
  header: string,
  pw: Uint8Array,
  salt: Uint8Array,
  mem: number,
  time: number,
  para: number,
  n: Uint8Array,
): string {
  const { Ek, Ak } = derive(pw, salt, mem, time, para);
  const edk = xchacha20(Ek, n, ptk);
  const params = concat(salt, be64(mem), be32(time), be32(para), n, edk);
  const t = blake2b(concat(utf8(header), params), { key: Ak, dkLen: 32 });
  return `${header}${b64uEncode(concat(params, t))}`;
}

export function wrapWithPassword(
  key: LocalKey | SecretKey,
  password: string | Uint8Array,
  opts: PwOpts = {},
): string {
  const header = key instanceof LocalKey ? LOCAL_H : SECRET_H;
  const mem = opts.memlimit ?? 67108864;
  const time = opts.opslimit ?? 2;
  const para = opts.parallelism ?? 1;
  return _wrapPw(key.bytes, header, toBytes(password), randomBytes(16), mem, time, para, randomBytes(24));
}

export function unwrapWithPassword(paserk: string, password: string | Uint8Array): LocalKey | SecretKey {
  let header: string;
  let isLocal: boolean;
  if (paserk.startsWith(LOCAL_H)) {
    header = LOCAL_H;
    isLocal = true;
  } else if (paserk.startsWith(SECRET_H)) {
    header = SECRET_H;
    isLocal = false;
  } else {
    throw new PaserkError('unsupported pw PASERK');
  }
  const body = b64uDecode(paserk.slice(header.length));
  const salt = body.slice(0, 16);
  const mem = readBe64(body.slice(16, 24));
  const time = readBe32(body, 24);
  const para = readBe32(body, 28);
  const n = body.slice(32, 56);
  const edk = body.slice(56, body.length - 32);
  const t = body.slice(body.length - 32);
  const { Ek, Ak } = derive(toBytes(password), salt, mem, time, para);
  const params = concat(salt, be64(mem), be32(time), be32(para), n, edk);
  const t2 = blake2b(concat(utf8(header), params), { key: Ak, dkLen: 32 });
  if (!timingSafeEqual(t, t2)) throw new PaserkError('password wrap authentication failed');
  const ptk = xchacha20(Ek, n, edk);
  if (isLocal) {
    if (ptk.length !== 32) throw new PaserkError('unwrapped local key must be 32 bytes');
    return new LocalKey(ptk);
  }
  if (ptk.length !== 64) throw new PaserkError('unwrapped secret key must be 64 bytes');
  return new SecretKey(ptk);
}
