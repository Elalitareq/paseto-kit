import { encryptRaw, decryptRaw } from './v3-local.js';
import { signRaw, verifyRaw } from './v3-public.js';
import {
  toBytes,
  encodePayload,
  decodePayload,
  runValidation,
  type Payload,
  type EncodeOpts,
  type DecodeOpts,
  type DecodeResult,
} from './marshal.js';
import { generateV3LocalKey, generateV3KeyPair } from '../keys/v3.js';
import type { V3LocalKey, V3SecretKey, V3PublicKey } from '../keys/v3.js';
import { toPaserkV3, fromPaserkV3, keyIdV3 } from '../paserk/v3-serialize.js';
import { wrapKeyV3, unwrapKeyV3 } from '../paserk/v3-wrap.js';
import { wrapWithPasswordV3, unwrapWithPasswordV3 } from '../paserk/v3-pw.js';
import { sealKeyV3, unsealKeyV3 } from '../paserk/v3-seal.js';

export function encrypt(key: V3LocalKey, payload: Payload, opts: EncodeOpts = {}): string {
  return encryptRaw(key, encodePayload(payload), toBytes(opts.footer), toBytes(opts.assertion));
}

export function decrypt(key: V3LocalKey, token: string, opts: DecodeOpts = {}): DecodeResult {
  const { message, footer } = decryptRaw(key, token, toBytes(opts.footer), toBytes(opts.assertion));
  const payload = decodePayload(message);
  runValidation(payload, opts);
  return { payload, footer };
}

export function sign(key: V3SecretKey, payload: Payload, opts: EncodeOpts = {}): string {
  return signRaw(key, encodePayload(payload), toBytes(opts.footer), toBytes(opts.assertion));
}

export function verify(key: V3PublicKey, token: string, opts: DecodeOpts = {}): DecodeResult {
  const { message, footer } = verifyRaw(key, token, toBytes(opts.footer), toBytes(opts.assertion));
  const payload = decodePayload(message);
  runValidation(payload, opts);
  return { payload, footer };
}

// Grouped namespace: `import { v3 } from 'paseto-kit'` → v3.encrypt(...)
export const v3 = {
  encrypt,
  decrypt,
  sign,
  verify,
  generateLocalKey: generateV3LocalKey,
  generateKeyPair: generateV3KeyPair,
  // PASERK
  toPaserk: toPaserkV3,
  fromPaserk: fromPaserkV3,
  keyId: keyIdV3,
  wrapKey: wrapKeyV3,
  unwrapKey: unwrapKeyV3,
  wrapWithPassword: wrapWithPasswordV3,
  unwrapWithPassword: unwrapWithPasswordV3,
  sealKey: sealKeyV3,
  unsealKey: unsealKeyV3,
};
