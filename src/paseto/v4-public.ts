import { ed25519 } from '@noble/curves/ed25519';
import { pae } from '../util/pae.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { b64uEncode } from '../util/b64.js';
import { splitToken } from '../util/validate.js';
import { VerifyError } from '../errors.js';
import type { SecretKey, PublicKey } from '../keys/types.js';

const H = 'v4.public.';

export function signRaw(
  key: SecretKey,
  message: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): string {
  const sig = ed25519.sign(pae([utf8(H), message, footer, assertion]), key.seed);
  const body = b64uEncode(concat(message, sig));
  return footer.length ? `${H}${body}.${b64uEncode(footer)}` : `${H}${body}`;
}

export function verifyRaw(
  key: PublicKey,
  token: string,
  footer: Uint8Array = new Uint8Array(),
  assertion: Uint8Array = new Uint8Array(),
): { message: Uint8Array; footer: Uint8Array } {
  const s = splitToken(token);
  if (s.header !== H) throw new VerifyError('wrong header');
  if (footer.length && !timingSafeEqual(footer, s.footer)) throw new VerifyError('footer mismatch');
  const sig = s.body.slice(-64);
  const message = s.body.slice(0, -64);
  if (!ed25519.verify(sig, pae([utf8(H), message, s.footer, assertion]), key.bytes)) {
    throw new VerifyError('signature verification failed');
  }
  return { message, footer: s.footer };
}
