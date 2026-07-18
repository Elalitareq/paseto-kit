import { b64uEncode, b64uDecode } from '../util/b64.js';
import { LocalKey, PublicKey, SecretKey } from '../keys/types.js';
import { PaserkError } from '../errors.js';

// k4.local / k4.public / k4.secret — a key serialized verbatim as base64url.
export function toPaserk(key: LocalKey | PublicKey | SecretKey): string {
  if (key instanceof LocalKey) return `k4.local.${b64uEncode(key.bytes)}`;
  if (key instanceof PublicKey) return `k4.public.${b64uEncode(key.bytes)}`;
  if (key instanceof SecretKey) return `k4.secret.${b64uEncode(key.bytes)}`;
  throw new PaserkError('unknown key type');
}

export function fromPaserk(s: string): LocalKey | PublicKey | SecretKey {
  if (s.startsWith('k4.local.')) return new LocalKey(b64uDecode(s.slice('k4.local.'.length)));
  if (s.startsWith('k4.public.')) return new PublicKey(b64uDecode(s.slice('k4.public.'.length)));
  if (s.startsWith('k4.secret.')) return new SecretKey(b64uDecode(s.slice('k4.secret.'.length)));
  throw new PaserkError('unsupported PASERK type');
}
