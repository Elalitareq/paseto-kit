import { encryptRaw, decryptRaw } from './v4-local.js';
import { signRaw, verifyRaw } from './v4-public.js';
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
import type { Validate } from './claims.js';
import type { LocalKey, SecretKey, PublicKey } from '../keys/types.js';

export function encrypt(key: LocalKey, payload: Payload, opts: EncodeOpts = {}): string {
  return encryptRaw(key, encodePayload(payload), toBytes(opts.footer), toBytes(opts.assertion));
}

export function decrypt(key: LocalKey, token: string, opts: DecodeOpts = {}): DecodeResult {
  const { message, footer } = decryptRaw(key, token, toBytes(opts.footer), toBytes(opts.assertion));
  const payload = decodePayload(message);
  runValidation(payload, opts);
  return { payload, footer };
}

export function sign(key: SecretKey, payload: Payload, opts: EncodeOpts = {}): string {
  return signRaw(key, encodePayload(payload), toBytes(opts.footer), toBytes(opts.assertion));
}

export function verify(key: PublicKey, token: string, opts: DecodeOpts = {}): DecodeResult {
  const { message, footer } = verifyRaw(key, token, toBytes(opts.footer), toBytes(opts.assertion));
  const payload = decodePayload(message);
  runValidation(payload, opts);
  return { payload, footer };
}

export type { Payload, EncodeOpts, DecodeOpts, DecodeResult, Validate };
