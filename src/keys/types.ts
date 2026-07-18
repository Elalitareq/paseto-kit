// v4 key material. LocalKey = 32-byte symmetric; Ed25519 SecretKey = 64 bytes
// (seed(32) || public(32)); PublicKey = 32 bytes.
export class LocalKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 32) throw new Error('local key must be 32 bytes');
  }
}
export class PublicKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 32) throw new Error('public key must be 32 bytes');
  }
}
export class SecretKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 64) throw new Error('secret key must be 64 bytes (seed || public)');
  }
  get seed(): Uint8Array {
    return this.bytes.slice(0, 32);
  }
  get publicKeyBytes(): Uint8Array {
    return this.bytes.slice(32);
  }
}
