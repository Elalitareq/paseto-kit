import { blake2b } from '@noble/hashes/blake2b';
import { xchacha20 } from '@noble/ciphers/chacha';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { randomBytes } from '../keys/generate.js';
import { LocalKey, SecretKey } from '../keys/types.js';
import { PaserkError } from '../errors.js';

const LOCAL_H = 'k4.local-wrap.pie.';
const SECRET_H = 'k4.secret-wrap.pie.';

// pie key-wrapping (v4): XChaCha20 + keyed BLAKE2b, domain tags 0x80/0x81.
function derive(wk: Uint8Array, n: Uint8Array): { Ek: Uint8Array; n2: Uint8Array; Ak: Uint8Array } {
  const x = blake2b(concat(Uint8Array.of(0x80), n), { key: wk, dkLen: 56 });
  return {
    Ek: x.slice(0, 32),
    n2: x.slice(32, 56),
    Ak: blake2b(concat(Uint8Array.of(0x81), n), { key: wk, dkLen: 32 }),
  };
}

export function _wrap(ptk: Uint8Array, wrappingKey: LocalKey, header: string, n: Uint8Array): string {
  const { Ek, n2, Ak } = derive(wrappingKey.bytes, n);
  const c = xchacha20(Ek, n2, ptk);
  const t = blake2b(concat(utf8(header), n, c), { key: Ak, dkLen: 32 });
  return `${header}${b64uEncode(concat(t, n, c))}`;
}

export function wrapKey(key: LocalKey | SecretKey, wrappingKey: LocalKey): string {
  const header = key instanceof LocalKey ? LOCAL_H : SECRET_H;
  return _wrap(key.bytes, wrappingKey, header, randomBytes(32));
}

export function unwrapKey(paserk: string, wrappingKey: LocalKey): LocalKey | SecretKey {
  let header: string;
  let isLocal: boolean;
  if (paserk.startsWith(LOCAL_H)) {
    header = LOCAL_H;
    isLocal = true;
  } else if (paserk.startsWith(SECRET_H)) {
    header = SECRET_H;
    isLocal = false;
  } else {
    throw new PaserkError('unsupported wrap PASERK');
  }
  const body = b64uDecode(paserk.slice(header.length));
  const t = body.slice(0, 32);
  const n = body.slice(32, 64);
  const c = body.slice(64);
  const { Ek, n2, Ak } = derive(wrappingKey.bytes, n);
  const t2 = blake2b(concat(utf8(header), n, c), { key: Ak, dkLen: 32 });
  if (!timingSafeEqual(t, t2)) throw new PaserkError('wrap authentication failed');
  const ptk = xchacha20(Ek, n2, c);
  if (isLocal) {
    if (ptk.length !== 32) throw new PaserkError('unwrapped local key must be 32 bytes');
    return new LocalKey(ptk);
  }
  if (ptk.length !== 64) throw new PaserkError('unwrapped secret key must be 64 bytes');
  return new SecretKey(ptk);
}
