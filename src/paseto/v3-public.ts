import { p384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha2';
import { pae } from '../util/pae.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { b64uEncode } from '../util/b64.js';
import { splitToken } from '../util/validate.js';
import { VerifyError } from '../errors.js';
import type { V3SecretKey, V3PublicKey } from '../keys/v3.js';

const H = 'v3.public.';

// v3.public binds the compressed public key into the PAE (pk first), then signs
// SHA-384(m2) with ECDSA P-384, emitting a 96-byte r||s signature.
export function signRaw(
  key: V3SecretKey,
  message: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): string {
  const pk = key.publicKeyBytes;
  const m2 = pae([pk, utf8(H), message, footer, assertion]);
  const sig = p384.sign(sha384(m2), key.bytes).toCompactRawBytes(); // r || s, 96 bytes
  const body = b64uEncode(concat(message, sig));
  return footer.length ? `${H}${body}.${b64uEncode(footer)}` : `${H}${body}`;
}

export function verifyRaw(
  key: V3PublicKey,
  token: string,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): { message: Uint8Array; footer: Uint8Array } {
  const s = splitToken(token);
  if (s.header !== H) throw new VerifyError('wrong header');
  if (footer.length && !timingSafeEqual(footer, s.footer)) throw new VerifyError('footer mismatch');
  const sig = s.body.slice(-96);
  const message = s.body.slice(0, -96);
  const m2 = pae([key.bytes, utf8(H), message, s.footer, assertion]);
  if (!p384.verify(sig, sha384(m2), key.bytes)) throw new VerifyError('signature verification failed');
  return { message, footer: s.footer };
}
