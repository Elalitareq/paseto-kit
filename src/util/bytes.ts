export function concat(...arrs: Uint8Array[]): Uint8Array {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

const ENC = new TextEncoder();
const DEC = new TextDecoder();
export const utf8 = (s: string): Uint8Array => ENC.encode(s);
export const fromUtf8 = (b: Uint8Array): string => DEC.decode(b);

// Constant-time equality. Length is not secret in our usages; a length
// mismatch short-circuits, otherwise every byte is compared.
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
