import { hmac } from '@noble/hashes/hmac';
import { sha384 } from '@noble/hashes/sha2';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { ctr } from '@noble/ciphers/aes';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { randomBytes } from '../keys/generate.js';
import { V3LocalKey, V3SecretKey } from '../keys/v3.js';
import { PaserkError } from '../errors.js';

const LOCAL_H = 'k3.local-pw.';
const SECRET_H = 'k3.secret-pw.';

export interface PwV3Opts {
  /** PBKDF2-SHA384 iteration count (default 100000). */
  iterations?: number;
}

function be32(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}
function readBe32(b: Uint8Array, off: number): number {
  return ((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0;
}
function toBytes(x: string | Uint8Array): Uint8Array {
  return typeof x === 'string' ? utf8(x) : x;
}

// PBKW (v3): PBKDF2-SHA384 pre-key → SHA-384-derived Ek/Ak → AES-256-CTR + HMAC-SHA384.
function derive(pw: Uint8Array, salt: Uint8Array, iterations: number) {
  const k = pbkdf2(sha384, pw, salt, { c: iterations, dkLen: 32 });
  return {
    Ek: sha384(concat(Uint8Array.of(0xff), k)).slice(0, 32),
    Ak: sha384(concat(Uint8Array.of(0xfe), k)),
  };
}

export function _wrapPwV3(
  ptk: Uint8Array,
  header: string,
  pw: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  n: Uint8Array,
): string {
  const { Ek, Ak } = derive(pw, salt, iterations);
  const edk = ctr(Ek, n).encrypt(ptk);
  const params = concat(salt, be32(iterations), n, edk);
  const t = hmac(sha384, Ak, concat(utf8(header), params));
  return `${header}${b64uEncode(concat(params, t))}`;
}

export function wrapWithPasswordV3(
  key: V3LocalKey | V3SecretKey,
  password: string | Uint8Array,
  opts: PwV3Opts = {},
): string {
  const header = key instanceof V3LocalKey ? LOCAL_H : SECRET_H;
  const iterations = opts.iterations ?? 100000;
  return _wrapPwV3(key.bytes, header, toBytes(password), randomBytes(32), iterations, randomBytes(16));
}

export function unwrapWithPasswordV3(paserk: string, password: string | Uint8Array): V3LocalKey | V3SecretKey {
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
  const salt = body.slice(0, 32);
  const iterations = readBe32(body, 32);
  const n = body.slice(36, 52);
  const edk = body.slice(52, body.length - 48);
  const t = body.slice(body.length - 48);
  const { Ek, Ak } = derive(toBytes(password), salt, iterations);
  const params = concat(salt, be32(iterations), n, edk);
  const t2 = hmac(sha384, Ak, concat(utf8(header), params));
  if (!timingSafeEqual(t, t2)) throw new PaserkError('password wrap authentication failed');
  const ptk = ctr(Ek, n).decrypt(edk);
  if (isLocal) {
    if (ptk.length !== 32) throw new PaserkError('unwrapped local key must be 32 bytes');
    return new V3LocalKey(ptk);
  }
  if (ptk.length !== 48) throw new PaserkError('unwrapped secret key must be 48 bytes');
  return new V3SecretKey(ptk);
}
