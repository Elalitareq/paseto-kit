// base64url (RFC 4648 §5), no padding. Pure, runtime-agnostic.
import { FormatError } from '../errors.js';

const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < A.length; i++) m[A[i]!] = i;
  return m;
})();

function sextet(s: string, i: number): number {
  const c = LOOKUP[s[i]!];
  if (c === undefined) throw new FormatError('invalid base64url character');
  return c;
}

export function b64uEncode(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += A[(n >> 18) & 63]! + A[(n >> 12) & 63]!;
    if (i + 1 < b.length) out += A[(n >> 6) & 63]!;
    if (i + 2 < b.length) out += A[n & 63]!;
  }
  return out;
}

// Strict decode: rejects invalid characters and non-canonical trailing bits
// (unused low bits of the final group MUST be zero), as PASETO/PASERK require.
export function b64uDecode(s: string): Uint8Array {
  const n = s.length;
  if (n % 4 === 1) throw new FormatError('invalid base64url length');
  const out = new Uint8Array(Math.floor((n * 3) / 4));
  let o = 0;
  for (let i = 0; i < n; i += 4) {
    const c0 = sextet(s, i);
    const c1 = sextet(s, i + 1);
    out[o++] = (c0 << 2) | (c1 >> 4);
    if (i + 2 < n) {
      const c2 = sextet(s, i + 2);
      out[o++] = ((c1 & 15) << 4) | (c2 >> 2);
      if (i + 3 < n) {
        out[o++] = ((c2 & 3) << 6) | sextet(s, i + 3);
      } else if (c2 & 3) {
        throw new FormatError('non-canonical base64url');
      }
    } else if (c1 & 15) {
      throw new FormatError('non-canonical base64url');
    }
  }
  return out;
}
