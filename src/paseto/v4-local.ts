import { blake2b } from '@noble/hashes/blake2b';
import { xchacha20 } from '@noble/ciphers/chacha';
import { pae } from '../util/pae.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { b64uEncode } from '../util/b64.js';
import { splitToken } from '../util/validate.js';
import { DecryptError } from '../errors.js';
import { randomBytes } from '../keys/generate.js';
import type { LocalKey } from '../keys/types.js';

const H = 'v4.local.';

// Derive encryption key Ek, XChaCha20 nonce n2, and auth key Ak from the input
// key and the random nonce, using domain-separated keyed BLAKE2b (spec).
function deriveKeys(key: Uint8Array, n: Uint8Array): { Ek: Uint8Array; n2: Uint8Array; Ak: Uint8Array } {
  const tmp = blake2b(concat(utf8('paseto-encryption-key'), n), { key, dkLen: 56 });
  return {
    Ek: tmp.slice(0, 32),
    n2: tmp.slice(32, 56),
    Ak: blake2b(concat(utf8('paseto-auth-key-for-aead'), n), { key, dkLen: 32 }),
  };
}

// Internal seam: nonce is injected so the encrypt path is testable against the
// official (deterministic) vectors. Public `encryptRaw` generates a fresh nonce.
export function _encrypt(
  key: LocalKey,
  message: Uint8Array,
  footer: Uint8Array,
  assertion: Uint8Array,
  n: Uint8Array,
): string {
  const { Ek, n2, Ak } = deriveKeys(key.bytes, n);
  const c = xchacha20(Ek, n2, message);
  const t = blake2b(pae([utf8(H), n, c, footer, assertion]), { key: Ak, dkLen: 32 });
  const body = b64uEncode(concat(n, c, t));
  return footer.length ? `${H}${body}.${b64uEncode(footer)}` : `${H}${body}`;
}

export function encryptRaw(
  key: LocalKey,
  message: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): string {
  return _encrypt(key, message, footer, assertion, randomBytes(32));
}

export function decryptRaw(
  key: LocalKey,
  token: string,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): { message: Uint8Array; footer: Uint8Array } {
  const s = splitToken(token);
  if (s.header !== H) throw new DecryptError('wrong header');
  if (footer.length && !timingSafeEqual(footer, s.footer)) throw new DecryptError('footer mismatch');
  const n = s.body.slice(0, 32);
  const t = s.body.slice(-32);
  const c = s.body.slice(32, -32);
  const { Ek, n2, Ak } = deriveKeys(key.bytes, n);
  const t2 = blake2b(pae([utf8(H), n, c, s.footer, assertion]), { key: Ak, dkLen: 32 });
  if (!timingSafeEqual(t, t2)) throw new DecryptError('authentication failed');
  return { message: xchacha20(Ek, n2, c), footer: s.footer };
}
