import { concat } from './bytes.js';

// LE64: 64-bit unsigned little-endian, most-significant bit cleared (spec).
function le64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  b[7] = b[7]! & 0x7f;
  return b;
}

// Pre-Authentication Encoding: PAE = LE64(count) || (LE64(len(p)) || p)*
export function pae(pieces: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [le64(pieces.length)];
  for (const p of pieces) {
    parts.push(le64(p.length), p);
  }
  return concat(...parts);
}
