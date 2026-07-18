import { blake2b } from '@noble/hashes/blake2b';
import { b64uEncode } from '../util/b64.js';
import { concat, utf8 } from '../util/bytes.js';
import { toPaserk } from './serialize.js';
import { LocalKey, PublicKey, SecretKey } from '../keys/types.js';
import { PaserkError } from '../errors.js';

// PASERK ID (v4): d = BLAKE2b(h || paserk, 33 bytes); return h || base64url(d).
export function keyId(key: LocalKey | PublicKey | SecretKey): string {
  let h: string;
  if (key instanceof LocalKey) h = 'k4.lid.';
  else if (key instanceof PublicKey) h = 'k4.pid.';
  else if (key instanceof SecretKey) h = 'k4.sid.';
  else throw new PaserkError('unknown key type');
  const d = blake2b(concat(utf8(h), utf8(toPaserk(key))), { dkLen: 33 });
  return `${h}${b64uEncode(d)}`;
}
