export { encrypt, decrypt, sign, verify } from './paseto/index.js';
export type { Payload, EncodeOpts, DecodeOpts, DecodeResult, Validate } from './paseto/index.js';
export { generateLocalKey, generateKeyPair, randomBytes } from './keys/generate.js';
export { LocalKey, SecretKey, PublicKey } from './keys/types.js';

// PASETO v3 (NIST: P-384 / AES-256-CTR / HMAC-SHA384). Top-level encrypt/decrypt/
// sign/verify remain v4; use the `v3` namespace for v3 tokens.
export { v3 } from './paseto/v3.js';
export { V3LocalKey, V3SecretKey, V3PublicKey, generateV3LocalKey, generateV3KeyPair } from './keys/v3.js';

// PASERK — key serialization, ids, and wrapping
export { toPaserk, fromPaserk } from './paserk/serialize.js';
export { keyId } from './paserk/id.js';
export { wrapKey, unwrapKey } from './paserk/wrap.js';
export { wrapWithPassword, unwrapWithPassword } from './paserk/pw.js';
export type { PwOpts } from './paserk/pw.js';
export { sealKey, unsealKey } from './paserk/seal.js';
export {
  PasetoError,
  FormatError,
  DecryptError,
  VerifyError,
  PaserkError,
  ClaimError,
} from './errors.js';

export const VERSION = '0.1.0';
