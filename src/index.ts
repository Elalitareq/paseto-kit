export { encrypt, decrypt, sign, verify } from './paseto/index.js';
export type { Payload, EncodeOpts, DecodeOpts, DecodeResult, Validate } from './paseto/index.js';
export { generateLocalKey, generateKeyPair, randomBytes } from './keys/generate.js';
export { LocalKey, SecretKey, PublicKey } from './keys/types.js';
export {
  PasetoError,
  FormatError,
  DecryptError,
  VerifyError,
  PaserkError,
  ClaimError,
} from './errors.js';

export const VERSION = '0.0.0';
