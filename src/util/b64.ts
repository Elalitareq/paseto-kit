// base64url (RFC 4648 §5), no padding. Pure, runtime-agnostic.
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < A.length; i++) m[A[i]!] = i;
  return m;
})();

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

export function b64uDecode(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 4) {
    const c0 = LOOKUP[s[i]!]!;
    const c1 = LOOKUP[s[i + 1]!]!;
    out.push((c0 << 2) | (c1 >> 4));
    if (s[i + 2] !== undefined) {
      const c2 = LOOKUP[s[i + 2]!]!;
      out.push(((c1 & 15) << 4) | (c2 >> 2));
      if (s[i + 3] !== undefined) {
        const c3 = LOOKUP[s[i + 3]!]!;
        out.push(((c2 & 3) << 6) | c3);
      }
    }
  }
  return new Uint8Array(out);
}
