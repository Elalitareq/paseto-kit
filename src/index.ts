export { encrypt, decrypt, sign, verify } from './paseto/index.js';
export type { Payload, EncodeOpts, DecodeOpts, DecodeResult, Validate } from './paseto/index.js';
export { generateLocalKey, generateKeyPair, randomBytes } from './keys/generate.js';
export { LocalKey, SecretKey, PublicKey } from './keys/types.js';

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

export const VERSION = '0.0.0';
