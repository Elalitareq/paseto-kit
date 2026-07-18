import { encryptRaw, decryptRaw } from './v4-local.js';
import { signRaw, verifyRaw } from './v4-public.js';
import { validateClaims, type Validate } from './claims.js';
import { utf8, fromUtf8 } from '../util/bytes.js';
import type { LocalKey, SecretKey, PublicKey } from '../keys/types.js';

export type Payload = Record<string, unknown> | string | Uint8Array;
export interface EncodeOpts {
  footer?: string | Uint8Array;
  assertion?: string | Uint8Array;
}
export interface DecodeOpts extends EncodeOpts {
  validate?: Validate;
}
export interface DecodeResult {
  payload: unknown;
  footer: Uint8Array;
}

function toBytes(x?: string | Uint8Array): Uint8Array {
  if (x === undefined) return new Uint8Array();
  return typeof x === 'string' ? utf8(x) : x;
}

function encodePayload(p: Payload): Uint8Array {
  if (p instanceof Uint8Array) return p;
  if (typeof p === 'string') return utf8(p);
  return utf8(JSON.stringify(p));
}

// Objects/arrays are returned parsed; anything else comes back as the raw string.
function decodePayload(bytes: Uint8Array): unknown {
  const s = fromUtf8(bytes);
  try {
    const o: unknown = JSON.parse(s);
    return typeof o === 'object' && o !== null ? o : s;
  } catch {
    return s;
  }
}

function runValidation(payload: unknown, opts?: DecodeOpts): void {
  if (opts?.validate && typeof payload === 'object' && payload !== null && !(payload instanceof Uint8Array)) {
    validateClaims(payload as Record<string, unknown>, opts.validate);
  }
}

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

export type { Validate };
