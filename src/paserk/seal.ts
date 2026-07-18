import { blake2b } from '@noble/hashes/blake2b';
import { xchacha20 } from '@noble/ciphers/chacha';
import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { b64uEncode, b64uDecode } from '../util/b64.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { randomBytes } from '../keys/generate.js';
import { LocalKey, PublicKey, SecretKey } from '../keys/types.js';
import { PaserkError } from '../errors.js';

const H = 'k4.seal.';

// PKE v4: wrap a local key for an Ed25519 recipient. Ek/Ak/n derived from the
// X25519 ECDH shared secret; XChaCha20 encrypts; keyed BLAKE2b authenticates.
export function _seal(pdk: Uint8Array, recipientPub: Uint8Array, esk: Uint8Array): string {
  const xpk = edwardsToMontgomeryPub(recipientPub);
  const epk = x25519.getPublicKey(esk);
  const xk = x25519.getSharedSecret(esk, xpk);
  const Ek = blake2b(concat(Uint8Array.of(0x01), utf8(H), xk, epk, xpk), { dkLen: 32 });
  const Ak = blake2b(concat(Uint8Array.of(0x02), utf8(H), xk, epk, xpk), { dkLen: 32 });
  const n = blake2b(concat(epk, xpk), { dkLen: 24 });
  const edk = xchacha20(Ek, n, pdk);
  const t = blake2b(concat(utf8(H), epk, edk), { key: Ak, dkLen: 32 });
  return `${H}${b64uEncode(concat(t, epk, edk))}`;
}

export function sealKey(key: LocalKey, recipientPublic: PublicKey): string {
  return _seal(key.bytes, recipientPublic.bytes, randomBytes(32));
}

export function unsealKey(paserk: string, recipientSecret: SecretKey): LocalKey {
  if (!paserk.startsWith(H)) throw new PaserkError('unsupported seal PASERK');
  const body = b64uDecode(paserk.slice(H.length));
  const t = body.slice(0, 32);
  const epk = body.slice(32, 64);
  const edk = body.slice(64);
  const xsk = edwardsToMontgomeryPriv(recipientSecret.seed);
  const xpk = edwardsToMontgomeryPub(recipientSecret.publicKeyBytes);
  const xk = x25519.getSharedSecret(xsk, epk);
  const Ak = blake2b(concat(Uint8Array.of(0x02), utf8(H), xk, epk, xpk), { dkLen: 32 });
  const t2 = blake2b(concat(utf8(H), epk, edk), { key: Ak, dkLen: 32 });
  if (!timingSafeEqual(t, t2)) throw new PaserkError('seal authentication failed');
  const Ek = blake2b(concat(Uint8Array.of(0x01), utf8(H), xk, epk, xpk), { dkLen: 32 });
  const n = blake2b(concat(epk, xpk), { dkLen: 24 });
  const pdk = xchacha20(Ek, n, edk);
  if (pdk.length !== 32) throw new PaserkError('unsealed local key must be 32 bytes');
  return new LocalKey(pdk);
}
