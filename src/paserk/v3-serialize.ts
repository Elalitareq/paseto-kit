import { sha384 } from '@noble/hashes/sha2';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8 } from '../util/bytes.js';
import { V3LocalKey, V3PublicKey, V3SecretKey } from '../keys/v3.js';
import { PaserkError } from '../errors.js';

export function toPaserkV3(key: V3LocalKey | V3PublicKey | V3SecretKey): string {
  if (key instanceof V3LocalKey) return `k3.local.${b64uEncode(key.bytes)}`;
  if (key instanceof V3PublicKey) return `k3.public.${b64uEncode(key.bytes)}`;
  if (key instanceof V3SecretKey) return `k3.secret.${b64uEncode(key.bytes)}`;
  throw new PaserkError('unknown key type');
}

export function fromPaserkV3(s: string): V3LocalKey | V3PublicKey | V3SecretKey {
  if (s.startsWith('k3.local.')) return new V3LocalKey(b64uDecode(s.slice('k3.local.'.length)));
  if (s.startsWith('k3.public.')) return new V3PublicKey(b64uDecode(s.slice('k3.public.'.length)));
  if (s.startsWith('k3.secret.')) return new V3SecretKey(b64uDecode(s.slice('k3.secret.'.length)));
  throw new PaserkError('unsupported PASERK type');
}

// PASERK ID (v3): d = SHA-384(h || paserk)[0:33]; return h || base64url(d).
export function keyIdV3(key: V3LocalKey | V3PublicKey | V3SecretKey): string {
  let h: string;
  if (key instanceof V3LocalKey) h = 'k3.lid.';
  else if (key instanceof V3PublicKey) h = 'k3.pid.';
  else if (key instanceof V3SecretKey) h = 'k3.sid.';
  else throw new PaserkError('unknown key type');
  const d = sha384(concat(utf8(h), utf8(toPaserkV3(key)))).slice(0, 33);
  return `${h}${b64uEncode(d)}`;
}
