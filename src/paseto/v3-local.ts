import { hkdf } from '@noble/hashes/hkdf';
import { sha384 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac';
import { ctr } from '@noble/ciphers/aes';
import { pae } from '../util/pae.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { b64uEncode } from '../util/b64.js';
import { splitToken } from '../util/validate.js';
import { DecryptError } from '../errors.js';
import { randomBytes } from '../keys/generate.js';
import type { V3LocalKey } from '../keys/v3.js';

const H = 'v3.local.';

// HKDF-SHA384 splits the input key into Ek (32) + CTR nonce n2 (16), and a
// separate 48-byte auth key Ak — with the random nonce mixed into the HKDF info.
function deriveKeys(key: Uint8Array, n: Uint8Array): { Ek: Uint8Array; n2: Uint8Array; Ak: Uint8Array } {
  const tmp = hkdf(sha384, key, undefined, concat(utf8('paseto-encryption-key'), n), 48);
  return {
    Ek: tmp.slice(0, 32),
    n2: tmp.slice(32, 48),
    Ak: hkdf(sha384, key, undefined, concat(utf8('paseto-auth-key-for-aead'), n), 48),
  };
}

export function _encrypt(
  key: V3LocalKey,
  message: Uint8Array,
  footer: Uint8Array,
  assertion: Uint8Array,
  n: Uint8Array,
): string {
  const { Ek, n2, Ak } = deriveKeys(key.bytes, n);
  const c = ctr(Ek, n2).encrypt(message);
  const t = hmac(sha384, Ak, pae([utf8(H), n, c, footer, assertion]));
  const body = b64uEncode(concat(n, c, t));
  return footer.length ? `${H}${body}.${b64uEncode(footer)}` : `${H}${body}`;
}

export function encryptRaw(
  key: V3LocalKey,
  message: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): string {
  return _encrypt(key, message, footer, assertion, randomBytes(32));
}

export function decryptRaw(
  key: V3LocalKey,
  token: string,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): { message: Uint8Array; footer: Uint8Array } {
  const s = splitToken(token);
  if (s.header !== H) throw new DecryptError('wrong header');
  if (footer.length && !timingSafeEqual(footer, s.footer)) throw new DecryptError('footer mismatch');
  const n = s.body.slice(0, 32);
  const t = s.body.slice(-48);
  const c = s.body.slice(32, -48);
  const { Ek, n2, Ak } = deriveKeys(key.bytes, n);
  const t2 = hmac(sha384, Ak, pae([utf8(H), n, c, s.footer, assertion]));
  if (!timingSafeEqual(t, t2)) throw new DecryptError('authentication failed');
  return { message: ctr(Ek, n2).decrypt(c), footer: s.footer };
}
