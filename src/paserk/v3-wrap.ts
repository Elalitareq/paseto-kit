import { hmac } from '@noble/hashes/hmac';
import { sha384 } from '@noble/hashes/sha2';
import { ctr } from '@noble/ciphers/aes';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { randomBytes } from '../keys/generate.js';
import { V3LocalKey, V3SecretKey } from '../keys/v3.js';
import { PaserkError } from '../errors.js';

const LOCAL_H = 'k3.local-wrap.pie.';
const SECRET_H = 'k3.secret-wrap.pie.';

// pie key-wrapping (v3): AES-256-CTR + HMAC-SHA384, domain tags 0x80/0x81.
function derive(wk: Uint8Array, n: Uint8Array): { Ek: Uint8Array; n2: Uint8Array; Ak: Uint8Array } {
  const x = hmac(sha384, wk, concat(Uint8Array.of(0x80), n));
  return {
    Ek: x.slice(0, 32),
    n2: x.slice(32, 48),
    // v3 truncates the HMAC-SHA384 auth key to 32 bytes (the spec doc omits this;
    // the paragonie reference makes it explicit).
    Ak: hmac(sha384, wk, concat(Uint8Array.of(0x81), n)).slice(0, 32),
  };
}

export function _wrapV3(ptk: Uint8Array, wrappingKey: V3LocalKey, header: string, n: Uint8Array): string {
  const { Ek, n2, Ak } = derive(wrappingKey.bytes, n);
  const c = ctr(Ek, n2).encrypt(ptk);
  const t = hmac(sha384, Ak, concat(utf8(header), n, c));
  return `${header}${b64uEncode(concat(t, n, c))}`;
}

export function wrapKeyV3(key: V3LocalKey | V3SecretKey, wrappingKey: V3LocalKey): string {
  const header = key instanceof V3LocalKey ? LOCAL_H : SECRET_H;
  return _wrapV3(key.bytes, wrappingKey, header, randomBytes(32));
}

export function unwrapKeyV3(paserk: string, wrappingKey: V3LocalKey): V3LocalKey | V3SecretKey {
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
  const t = body.slice(0, 48);
  const n = body.slice(48, 80);
  const c = body.slice(80);
  const { Ek, n2, Ak } = derive(wrappingKey.bytes, n);
  const t2 = hmac(sha384, Ak, concat(utf8(header), n, c));
  if (!timingSafeEqual(t, t2)) throw new PaserkError('wrap authentication failed');
  const ptk = ctr(Ek, n2).decrypt(c);
  if (isLocal) {
    if (ptk.length !== 32) throw new PaserkError('unwrapped local key must be 32 bytes');
    return new V3LocalKey(ptk);
  }
  if (ptk.length !== 48) throw new PaserkError('unwrapped secret key must be 48 bytes');
  return new V3SecretKey(ptk);
}
