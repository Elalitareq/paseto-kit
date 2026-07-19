import { p384 } from '@noble/curves/p384';
import { randomBytes } from './generate.js';

// v3 key material. V3LocalKey = 32-byte symmetric; P-384 V3SecretKey = 48-byte
// scalar; V3PublicKey = 49-byte compressed point (0x02/0x03 || X).
export class V3LocalKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 32) throw new Error('v3 local key must be 32 bytes');
  }
}
export class V3PublicKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 49) throw new Error('v3 public key must be 49 bytes (compressed P-384)');
  }
}
export class V3SecretKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 48) throw new Error('v3 secret key must be 48 bytes (P-384 scalar)');
  }
  get publicKeyBytes(): Uint8Array {
    return p384.getPublicKey(this.bytes, true); // compressed
  }
}

export function generateV3LocalKey(): V3LocalKey {
  return new V3LocalKey(randomBytes(32));
}

export function generateV3KeyPair(): { secretKey: V3SecretKey; publicKey: V3PublicKey } {
  const sk = p384.utils.randomPrivateKey(); // 48-byte scalar
  const pk = p384.getPublicKey(sk, true); // 49-byte compressed
  return { secretKey: new V3SecretKey(sk), publicKey: new V3PublicKey(pk) };
}
