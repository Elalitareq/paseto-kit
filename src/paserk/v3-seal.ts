import { p384 } from '@noble/curves/p384';
import { hmac } from '@noble/hashes/hmac';
import { sha384 } from '@noble/hashes/sha2';
import { ctr } from '@noble/ciphers/aes';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { V3LocalKey, V3PublicKey, V3SecretKey } from '../keys/v3.js';
import { PaserkError } from '../errors.js';

const H = 'k3.seal.';

// P-384 ECDH shared secret X-coordinate (48 bytes).
function ecdhX(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  return p384.getSharedSecret(priv, pub).slice(1); // drop 0x02/0x03 prefix
}

// PKE v3: wrap a v3 local key for a P-384 recipient using ECDH + SHA-384 + AES-CTR.
export function _sealV3(pdk: Uint8Array, recipientPub: Uint8Array, esk: Uint8Array): string {
  const epk = p384.getPublicKey(esk, true); // compressed, 49 bytes
  const xk = ecdhX(esk, recipientPub);
  const ekn = sha384(concat(Uint8Array.of(0x01), utf8(H), xk, epk, recipientPub));
  const Ek = ekn.slice(0, 32);
  const n = ekn.slice(32, 48);
  const Ak = sha384(concat(Uint8Array.of(0x02), utf8(H), xk, epk, recipientPub));
  const edk = ctr(Ek, n).encrypt(pdk);
  const t = hmac(sha384, Ak, concat(utf8(H), epk, edk));
  return `${H}${b64uEncode(concat(t, epk, edk))}`;
}

export function sealKeyV3(key: V3LocalKey, recipientPublic: V3PublicKey): string {
  return _sealV3(key.bytes, recipientPublic.bytes, p384.utils.randomPrivateKey());
}

export function unsealKeyV3(paserk: string, recipientSecret: V3SecretKey): V3LocalKey {
  if (!paserk.startsWith(H)) throw new PaserkError('unsupported seal PASERK');
  const body = b64uDecode(paserk.slice(H.length));
  const t = body.slice(0, 48);
  const epk = body.slice(48, 97); // compressed P-384, 49 bytes
  const edk = body.slice(97);
  const pk = p384.getPublicKey(recipientSecret.bytes, true);
  const xk = ecdhX(recipientSecret.bytes, epk);
  const Ak = sha384(concat(Uint8Array.of(0x02), utf8(H), xk, epk, pk));
  const t2 = hmac(sha384, Ak, concat(utf8(H), epk, edk));
  if (!timingSafeEqual(t, t2)) throw new PaserkError('seal authentication failed');
  const ekn = sha384(concat(Uint8Array.of(0x01), utf8(H), xk, epk, pk));
  const pdk = ctr(ekn.slice(0, 32), ekn.slice(32, 48)).decrypt(edk);
  if (pdk.length !== 32) throw new PaserkError('unsealed local key must be 32 bytes');
  return new V3LocalKey(pdk);
}
