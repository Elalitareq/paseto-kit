import { validateClaims, type Validate } from './claims.js';
import { utf8, fromUtf8 } from '../util/bytes.js';

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

export function toBytes(x?: string | Uint8Array): Uint8Array {
  if (x === undefined) return new Uint8Array();
  return typeof x === 'string' ? utf8(x) : x;
}

export function encodePayload(p: Payload): Uint8Array {
  if (p instanceof Uint8Array) return p;
  if (typeof p === 'string') return utf8(p);
  return utf8(JSON.stringify(p));
}

// Objects/arrays are returned parsed; anything else comes back as the raw string.
export function decodePayload(bytes: Uint8Array): unknown {
  const s = fromUtf8(bytes);
  try {
    const o: unknown = JSON.parse(s);
    return typeof o === 'object' && o !== null ? o : s;
  } catch {
    return s;
  }
}

export function runValidation(payload: unknown, opts?: DecodeOpts): void {
  if (
    opts?.validate &&
    typeof payload === 'object' &&
    payload !== null &&
    !(payload instanceof Uint8Array)
  ) {
    validateClaims(payload as Record<string, unknown>, opts.validate);
  }
}
