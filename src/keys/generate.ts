import { ed25519 } from '@noble/curves/ed25519';
import { LocalKey, SecretKey, PublicKey } from './types.js';
import { concat } from '../util/bytes.js';

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function generateLocalKey(): LocalKey {
  return new LocalKey(randomBytes(32));
}

export function generateKeyPair(): { secretKey: SecretKey; publicKey: PublicKey } {
  const seed = ed25519.utils.randomPrivateKey(); // 32-byte seed
  const pub = ed25519.getPublicKey(seed); // 32-byte public key
  return { secretKey: new SecretKey(concat(seed, pub)), publicKey: new PublicKey(pub) };
}
