# paseto-kit v1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `paseto-kit` v1.0 — a runtime-agnostic PASETO **v4** (local + public) library with **full PASERK** key management, conformant to the official test vectors.

**Architecture:** Layered pure→crypto→protocol→keys modules over audited `@noble/*` primitives, operating on `Uint8Array` only (no `node:crypto`, no `Buffer`). Correctness is proven by the PASETO/PASERK official known-answer vectors; non-deterministic operations (random nonce) expose an internal seam that accepts an injected nonce so the encrypt vectors are testable.

**Tech Stack:** TypeScript (strict), Vitest, tsup (dual ESM/CJS), `@noble/ciphers` · `@noble/hashes` · `@noble/curves`, npm.

## Global Constraints

- Runtime-agnostic: only `Uint8Array` + `globalThis.crypto.getRandomValues`. **No** `node:*` imports, **no** `Buffer`, in `src/`.
- Zero runtime dependencies except `@noble/ciphers`, `@noble/hashes`, `@noble/curves`.
- All MAC/footer/tag comparisons **constant-time**.
- base64url = RFC 4648 **without** padding.
- Package name: `paseto-kit`. License: MIT. Node floor for tooling: 18+.
- Every crypto task asserts against the **official vectors** committed under `test/vectors/`.
- Errors never contain key material or plaintext.

---

### Task 0: Repository scaffold

**Files:**
- Create: `package.json`, `tsconfig.json`, `vitest.config.ts`, `tsup.config.ts`, `.gitignore`, `src/index.ts` (placeholder), `test/smoke.test.ts`

**Interfaces:**
- Produces: buildable/testable repo; `npm test` and `npm run build` work.

- [ ] **Step 1: Write `.gitignore`**

```
node_modules/
dist/
coverage/
*.log
```

- [ ] **Step 2: Write `package.json`**

```json
{
  "name": "paseto-kit",
  "version": "0.0.0",
  "description": "Complete, runtime-agnostic PASETO v4 + full PASERK for JS/TS. Successor to panva/paseto.",
  "type": "module",
  "license": "MIT",
  "sideEffects": false,
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js", "require": "./dist/index.cjs" }
  },
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "files": ["dist"],
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@noble/ciphers": "^1.0.0",
    "@noble/curves": "^1.6.0",
    "@noble/hashes": "^1.5.0"
  },
  "devDependencies": {
    "tsup": "^8.0.0",
    "typescript": "^5.5.0",
    "vitest": "^2.0.0"
  }
}
```

- [ ] **Step 3: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "declaration": true,
    "verbatimModuleSyntax": true,
    "skipLibCheck": true,
    "lib": ["ES2022", "DOM"],
    "types": []
  },
  "include": ["src", "test"]
}
```

- [ ] **Step 4: Write `tsup.config.ts`**

```ts
import { defineConfig } from 'tsup';
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  treeshake: true,
});
```

- [ ] **Step 5: Write `vitest.config.ts`**

```ts
import { defineConfig } from 'vitest/config';
export default defineConfig({ test: { include: ['test/**/*.test.ts'] } });
```

- [ ] **Step 6: Placeholder `src/index.ts` + `test/smoke.test.ts`**

```ts
// src/index.ts
export const VERSION = '0.0.0';
```

```ts
// test/smoke.test.ts
import { expect, test } from 'vitest';
import { VERSION } from '../src/index.js';
test('module loads', () => { expect(VERSION).toBe('0.0.0'); });
```

- [ ] **Step 7: Install + run**

Run: `npm install && npm test`
Expected: 1 test passes.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "chore: scaffold paseto-kit (ts, vitest, tsup, @noble)"
```

---

### Task 1: base64url

**Files:**
- Create: `src/util/b64.ts`, `test/util/b64.test.ts`

**Interfaces:**
- Produces: `b64uEncode(b: Uint8Array): string`, `b64uDecode(s: string): Uint8Array` (no padding, RFC 4648 url alphabet).

- [ ] **Step 1: Failing test**

```ts
import { expect, test } from 'vitest';
import { b64uEncode, b64uDecode } from '../../src/util/b64.js';
test('roundtrip + known vector', () => {
  const bytes = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
  expect(b64uEncode(bytes)).toBe('aGVsbG8'); // no padding
  expect(b64uDecode('aGVsbG8')).toEqual(bytes);
});
test('no padding, url-safe chars', () => {
  const b = new Uint8Array([0xff, 0xff, 0xfe]);
  const s = b64uEncode(b);
  expect(s).not.toContain('=');
  expect(s).not.toMatch(/[+/]/);
  expect(b64uDecode(s)).toEqual(b);
});
```

- [ ] **Step 2: Run → FAIL** — `npx vitest run test/util/b64.test.ts` (module not found).

- [ ] **Step 3: Implement** (pure, no `Buffer`)

```ts
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP = /* built from A */ (() => { const m: Record<string, number> = {}; for (let i = 0; i < A.length; i++) m[A[i]!] = i; return m; })();

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
    const c0 = LOOKUP[s[i]!]!, c1 = LOOKUP[s[i + 1]!]!;
    out.push((c0 << 2) | (c1 >> 4));
    if (s[i + 2] !== undefined) { const c2 = LOOKUP[s[i + 2]!]!; out.push(((c1 & 15) << 4) | (c2 >> 2));
      if (s[i + 3] !== undefined) { const c3 = LOOKUP[s[i + 3]!]!; out.push(((c2 & 3) << 6) | c3); } }
  }
  return new Uint8Array(out);
}
```

- [ ] **Step 4: Run → PASS**.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: base64url (no padding)"`

---

### Task 2: bytes helpers

**Files:**
- Create: `src/util/bytes.ts`, `test/util/bytes.test.ts`

**Interfaces:**
- Produces: `concat(...a: Uint8Array[]): Uint8Array`, `utf8(s: string): Uint8Array`, `fromUtf8(b: Uint8Array): string`, `timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean`.

- [ ] **Step 1: Failing test**

```ts
import { expect, test } from 'vitest';
import { concat, utf8, fromUtf8, timingSafeEqual } from '../../src/util/bytes.js';
test('concat', () => { expect(concat(new Uint8Array([1]), new Uint8Array([2,3]))).toEqual(new Uint8Array([1,2,3])); });
test('utf8 roundtrip', () => { expect(fromUtf8(utf8('héllo'))).toBe('héllo'); });
test('timingSafeEqual', () => {
  expect(timingSafeEqual(new Uint8Array([1,2]), new Uint8Array([1,2]))).toBe(true);
  expect(timingSafeEqual(new Uint8Array([1,2]), new Uint8Array([1,3]))).toBe(false);
  expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1,2]))).toBe(false);
});
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement**

```ts
export function concat(...arrs: Uint8Array[]): Uint8Array {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
const ENC = new TextEncoder(); const DEC = new TextDecoder();
export const utf8 = (s: string) => ENC.encode(s);
export const fromUtf8 = (b: Uint8Array) => DEC.decode(b);
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
```

- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: byte helpers + constant-time compare"`

---

### Task 3: PAE (Pre-Authentication Encoding)

**Files:**
- Create: `src/util/pae.ts`, `test/util/pae.test.ts`

**Interfaces:**
- Produces: `pae(pieces: Uint8Array[]): Uint8Array`.
- Spec: `PAE = LE64(count) || for each p: LE64(len(p)) || p`; `LE64` = 8-byte little-endian, **top bit cleared**.

- [ ] **Step 1: Failing test** (official PAE known answers)

```ts
import { expect, test } from 'vitest';
import { pae } from '../../src/util/pae.js';
import { b64uEncode } from '../../src/util/b64.js';
const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
test('PAE([]) = LE64(0)', () => { expect(hex(pae([]))).toBe('0000000000000000'); });
test('PAE([""]) ', () => { expect(hex(pae([new Uint8Array()]))).toBe('0100000000000000' + '0000000000000000'); });
test('PAE(["test"])', () => {
  const t = new TextEncoder().encode('test');
  expect(hex(pae([t]))).toBe('0100000000000000' + '0400000000000000' + '74657374');
});
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement**

```ts
import { concat } from './bytes.js';
function le64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
  b[7]! &= 0x7f; // clear MSB per spec
  return b;
}
export function pae(pieces: Uint8Array[]): Uint8Array {
  const parts = [le64(pieces.length)];
  for (const p of pieces) { parts.push(le64(p.length), p); }
  return concat(...parts);
}
```

- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: PAE encoding"`

---

### Task 4: validate helpers

**Files:**
- Create: `src/util/validate.ts`, `src/errors.ts`, `test/util/validate.test.ts`

**Interfaces:**
- Produces error classes: `PasetoError`, `FormatError`, `DecryptError`, `VerifyError`, `ClaimError`, `PaserkError` (all extend `PasetoError`; `ClaimError` has `.claim: string`).
- Produces: `splitToken(token: string): { header: string; body: Uint8Array; footer: Uint8Array }` — splits `vX.purpose.` prefix, base64url body, optional `.footer`. Throws `FormatError` on malformed input.

- [ ] **Step 1: Failing test**

```ts
import { expect, test } from 'vitest';
import { splitToken } from '../../src/util/validate.js';
import { FormatError } from '../../src/errors.js';
test('splits header/body/footer', () => {
  const r = splitToken('v4.local.aGVsbG8.d29ybGQ');
  expect(r.header).toBe('v4.local.');
  expect(new TextDecoder().decode(r.footer)).toBe('world');
});
test('rejects malformed', () => { expect(() => splitToken('nope')).toThrow(FormatError); });
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement**

```ts
// src/errors.ts
export class PasetoError extends Error {}
export class FormatError extends PasetoError {}
export class DecryptError extends PasetoError {}
export class VerifyError extends PasetoError {}
export class PaserkError extends PasetoError {}
export class ClaimError extends PasetoError { constructor(public claim: string, msg: string) { super(msg); } }
```

```ts
// src/util/validate.ts
import { b64uDecode } from './b64.js';
import { FormatError } from '../errors.js';
export function splitToken(token: string) {
  const parts = token.split('.');
  if (parts.length !== 3 && parts.length !== 4) throw new FormatError('invalid token structure');
  const [version, purpose] = parts;
  if (version !== 'v4') throw new FormatError('unsupported version');
  if (purpose !== 'local' && purpose !== 'public') throw new FormatError('unsupported purpose');
  return {
    header: `${version}.${purpose}.`,
    body: b64uDecode(parts[2]!),
    footer: parts[3] ? b64uDecode(parts[3]) : new Uint8Array(),
    purpose,
  };
}
```

- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: errors + token splitter"`

---

### Task 5: v4 keys — types & generation

**Files:**
- Create: `src/keys/types.ts`, `src/keys/generate.ts`, `test/keys/generate.test.ts`

**Interfaces:**
- Produces:
  - `class LocalKey { readonly bytes: Uint8Array /* 32 */ }`
  - `class SecretKey { readonly bytes: Uint8Array /* 64: seed(32)||pub(32) */ }`
  - `class PublicKey { readonly bytes: Uint8Array /* 32 */ }`
  - `generateLocalKey(): LocalKey`
  - `generateKeyPair(): { secretKey: SecretKey; publicKey: PublicKey }`
  - `randomBytes(n: number): Uint8Array` (via `globalThis.crypto.getRandomValues`)

- [ ] **Step 1: Failing test**

```ts
import { expect, test } from 'vitest';
import { generateLocalKey, generateKeyPair } from '../../src/keys/generate.js';
test('local key is 32 bytes', () => { expect(generateLocalKey().bytes.length).toBe(32); });
test('keypair sizes + linkage', () => {
  const { secretKey, publicKey } = generateKeyPair();
  expect(secretKey.bytes.length).toBe(64);
  expect(publicKey.bytes.length).toBe(32);
  expect(secretKey.bytes.slice(32)).toEqual(publicKey.bytes); // pub is tail of secret
});
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** (Ed25519 from `@noble/curves`)

```ts
// src/keys/types.ts
export class LocalKey { constructor(public readonly bytes: Uint8Array) { if (bytes.length !== 32) throw new Error('local key must be 32 bytes'); } }
export class PublicKey { constructor(public readonly bytes: Uint8Array) { if (bytes.length !== 32) throw new Error('public key must be 32 bytes'); } }
export class SecretKey { constructor(public readonly bytes: Uint8Array) { if (bytes.length !== 64) throw new Error('secret key must be 64 bytes'); } }
```

```ts
// src/keys/generate.ts
import { ed25519 } from '@noble/curves/ed25519';
import { LocalKey, SecretKey, PublicKey } from './types.js';
import { concat } from '../util/bytes.js';
export function randomBytes(n: number): Uint8Array { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; }
export function generateLocalKey(): LocalKey { return new LocalKey(randomBytes(32)); }
export function generateKeyPair() {
  const seed = ed25519.utils.randomPrivateKey();       // 32-byte seed
  const pub = ed25519.getPublicKey(seed);              // 32-byte public
  return { secretKey: new SecretKey(concat(seed, pub)), publicKey: new PublicKey(pub) };
}
```

> **Executor note:** verify the exact `@noble/curves` v1.x export path/method names against installed version; adjust import if the API differs. Vectors in Task 7 will catch any mismatch.

- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: v4 key types + generation"`

---

### Task 6: v4.local encrypt / decrypt

**Files:**
- Create: `src/paseto/v4-local.ts`, `test/vectors/v4-local.vectors.json` (from official repo), `test/paseto/v4-local.test.ts`

**Interfaces:**
- Consumes: `pae`, `b64uEncode/Decode`, `concat`, `timingSafeEqual`, `LocalKey`, `randomBytes`.
- Produces:
  - internal `_encrypt(key, message: Uint8Array, footer: Uint8Array, assertion: Uint8Array, nonce: Uint8Array): string`
  - public `encryptRaw(key: LocalKey, message: Uint8Array, footer?, assertion?): string`
  - public `decryptRaw(key: LocalKey, token: string, footer?, assertion?): { message: Uint8Array; footer: Uint8Array }`
- **Construction (spec):** `Ek||n2 = BLAKE2b(dkLen=56, key, "paseto-encryption-key"||n)`; `Ak = BLAKE2b(dkLen=32, key, "paseto-auth-key-for-aead"||n)`; `c = XChaCha20(Ek, n2, message)`; `t = BLAKE2b(dkLen=32, key=Ak, pae([h,n,c,f,i]))`; body = `n||c||t`.

- [ ] **Step 1: Fetch official vectors** — download `v4.local` cases from `paseto-standard/test-vectors` into `test/vectors/v4-local.vectors.json` (fields: `key`, `nonce`, `token`, `payload`, `footer`, `implicit-assertion`). Commit the file.

- [ ] **Step 2: Failing test** (vector-driven; inject the vector nonce)

```ts
import { expect, test } from 'vitest';
import vectors from '../vectors/v4-local.vectors.json';
import { _encrypt, decryptRaw } from '../../src/paseto/v4-local.js';
import { LocalKey } from '../../src/keys/types.js';
const hexToBytes = (h: string) => new Uint8Array(h.match(/../g)!.map(x => parseInt(x, 16)));
const utf8 = (s: string) => new TextEncoder().encode(s);
for (const v of vectors.tests.filter((t: any) => !t['expect-fail'])) {
  test(`v4.local encrypt: ${v.name}`, () => {
    const token = _encrypt(new LocalKey(hexToBytes(v.key)), utf8(v.payload),
      utf8(v.footer ?? ''), utf8(v['implicit-assertion'] ?? ''), hexToBytes(v.nonce));
    expect(token).toBe(v.token);
  });
  test(`v4.local decrypt: ${v.name}`, () => {
    const { message } = decryptRaw(new LocalKey(hexToBytes(v.key)), v.token,
      utf8(v.footer ?? ''), utf8(v['implicit-assertion'] ?? ''));
    expect(new TextDecoder().decode(message)).toBe(v.payload);
  });
}
```

- [ ] **Step 3: Run → FAIL**.

- [ ] **Step 4: Implement**

```ts
import { blake2b } from '@noble/hashes/blake2b';
import { xchacha20 } from '@noble/ciphers/chacha';
import { pae } from '../util/pae.js';
import { concat, utf8, timingSafeEqual } from '../util/bytes.js';
import { b64uEncode } from '../util/b64.js';
import { splitToken } from '../util/validate.js';
import { DecryptError } from '../errors.js';
import { randomBytes } from '../keys/generate.js';
import type { LocalKey } from '../keys/types.js';

const H = 'v4.local.';
function keys(key: Uint8Array, n: Uint8Array) {
  const tmp = blake2b(concat(utf8('paseto-encryption-key'), n), { key, dkLen: 56 });
  return { Ek: tmp.slice(0, 32), n2: tmp.slice(32, 56), Ak: blake2b(concat(utf8('paseto-auth-key-for-aead'), n), { key, dkLen: 32 }) };
}
export function _encrypt(key: LocalKey, message: Uint8Array, footer: Uint8Array, assertion: Uint8Array, n: Uint8Array): string {
  const { Ek, n2, Ak } = keys(key.bytes, n);
  const c = xchacha20(Ek, n2, message);
  const t = blake2b(pae([utf8(H), n, c, footer, assertion]), { key: Ak, dkLen: 32 });
  const body = b64uEncode(concat(n, c, t));
  return footer.length ? `${H}${body}.${b64uEncode(footer)}` : `${H}${body}`;
}
export function encryptRaw(key: LocalKey, message: Uint8Array, footer = new Uint8Array(), assertion = new Uint8Array()): string {
  return _encrypt(key, message, footer, assertion, randomBytes(32));
}
export function decryptRaw(key: LocalKey, token: string, footer = new Uint8Array(), assertion = new Uint8Array()) {
  const s = splitToken(token);
  if (s.header !== H) throw new DecryptError('wrong header');
  const n = s.body.slice(0, 32), t = s.body.slice(-32), c = s.body.slice(32, -32);
  const { Ek, n2, Ak } = keys(key.bytes, n);
  const t2 = blake2b(pae([utf8(H), n, c, s.footer, assertion]), { key: Ak, dkLen: 32 });
  if (!timingSafeEqual(t, t2)) throw new DecryptError('authentication failed');
  return { message: xchacha20(Ek, n2, c), footer: s.footer };
}
```

> **Executor note:** confirm `xchacha20(key, nonce, data)` signature in installed `@noble/ciphers` (it may be `xchacha20(key,nonce,data)` returning a keystream-XOR). Adjust if the current API returns a cipher object. The encrypt vector assertion is the ground truth.

- [ ] **Step 5: Run → PASS** (all v4.local vectors). **Step 6: Commit** — `git commit -am "feat: v4.local encrypt/decrypt (vectors green)"`

---

### Task 7: v4.public sign / verify

**Files:**
- Create: `src/paseto/v4-public.ts`, `test/vectors/v4-public.vectors.json`, `test/paseto/v4-public.test.ts`

**Interfaces:**
- Produces: `signRaw(key: SecretKey, message: Uint8Array, footer?, assertion?): string`; `verifyRaw(key: PublicKey, token: string, footer?, assertion?): { message; footer }`.
- **Construction:** `sig = Ed25519.sign(pae([h,m,f,i]), seed)`; body = `m||sig`.

- [ ] **Step 1: Fetch official `v4.public` vectors** → `test/vectors/v4-public.vectors.json`, commit.

- [ ] **Step 2: Failing test** (Ed25519 sign is deterministic → assert token equality + verify)

```ts
import { expect, test } from 'vitest';
import vectors from '../vectors/v4-public.vectors.json';
import { signRaw, verifyRaw } from '../../src/paseto/v4-public.js';
import { SecretKey, PublicKey } from '../../src/keys/types.js';
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map(x => parseInt(x, 16)));
const u = (s: string) => new TextEncoder().encode(s);
for (const v of vectors.tests.filter((t: any) => !t['expect-fail'])) {
  test(`v4.public sign: ${v.name}`, () => {
    expect(signRaw(new SecretKey(hb(v['secret-key'])), u(v.payload), u(v.footer ?? ''), u(v['implicit-assertion'] ?? ''))).toBe(v.token);
  });
  test(`v4.public verify: ${v.name}`, () => {
    const { message } = verifyRaw(new PublicKey(hb(v['public-key'])), v.token, u(v.footer ?? ''), u(v['implicit-assertion'] ?? ''));
    expect(new TextDecoder().decode(message)).toBe(v.payload);
  });
}
```

- [ ] **Step 3: Run → FAIL**.

- [ ] **Step 4: Implement**

```ts
import { ed25519 } from '@noble/curves/ed25519';
import { pae } from '../util/pae.js';
import { concat, utf8 } from '../util/bytes.js';
import { b64uEncode } from '../util/b64.js';
import { splitToken } from '../util/validate.js';
import { VerifyError } from '../errors.js';
import type { SecretKey, PublicKey } from '../keys/types.js';
const H = 'v4.public.';
export function signRaw(key: SecretKey, message: Uint8Array, footer = new Uint8Array(), assertion = new Uint8Array()): string {
  const seed = key.bytes.slice(0, 32);
  const sig = ed25519.sign(pae([utf8(H), message, footer, assertion]), seed);
  const body = b64uEncode(concat(message, sig));
  return footer.length ? `${H}${body}.${b64uEncode(footer)}` : `${H}${body}`;
}
export function verifyRaw(key: PublicKey, token: string, footer = new Uint8Array(), assertion = new Uint8Array()) {
  const s = splitToken(token);
  if (s.header !== H) throw new VerifyError('wrong header');
  const sig = s.body.slice(-64), message = s.body.slice(0, -64);
  if (!ed25519.verify(sig, pae([utf8(H), message, s.footer, assertion]), key.bytes)) throw new VerifyError('signature verification failed');
  return { message, footer: s.footer };
}
```

- [ ] **Step 5: Run → PASS**. **Step 6: Commit** — `git commit -am "feat: v4.public sign/verify (vectors green)"`

---

### Task 8: Claims & high-level encode/decode

**Files:**
- Create: `src/paseto/claims.ts`, `src/paseto/index.ts`, `test/paseto/claims.test.ts`

**Interfaces:**
- Produces:
  - `encrypt(key: LocalKey, payload: object | string | Uint8Array, opts?: EncodeOpts): string`
  - `decrypt(key: LocalKey, token: string, opts?: DecodeOpts): { payload: any; footer: Uint8Array }`
  - `sign(key: SecretKey, payload, opts?): string`; `verify(key: PublicKey, token, opts?): { payload; footer }`
  - `EncodeOpts = { footer?: string | Uint8Array; assertion?: string | Uint8Array }`
  - `DecodeOpts = EncodeOpts & { validate?: { exp?: boolean; nbf?: boolean; iss?: string; aud?: string; sub?: string; clockToleranceSec?: number } }`
- Object payloads are JSON-encoded; on decode, if the bytes parse as JSON object → return object, else return string. `validate` runs only for object payloads.

- [ ] **Step 1: Failing test**

```ts
import { expect, test } from 'vitest';
import { encrypt, decrypt } from '../../src/paseto/index.js';
import { generateLocalKey } from '../../src/keys/generate.js';
import { ClaimError } from '../../src/errors.js';
test('object payload roundtrip', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { sub: 'abc', data: 1 });
  expect(decrypt(k, t).payload).toMatchObject({ sub: 'abc', data: 1 });
});
test('expired token rejected', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { exp: new Date(Date.now() - 60000).toISOString() });
  expect(() => decrypt(k, t, { validate: { exp: true } })).toThrow(ClaimError);
});
test('audience mismatch rejected', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { aud: 'a' });
  expect(() => decrypt(k, t, { validate: { aud: 'b' } })).toThrow(ClaimError);
});
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** `claims.ts` (validate `exp`/`nbf` ISO-8601 with tolerance; `iss`/`aud`/`sub` equality → throw `ClaimError(claim, msg)`) and `index.ts` (payload marshalling around `encryptRaw`/`decryptRaw`/`signRaw`/`verifyRaw`, coercing `opts.footer`/`opts.assertion` strings to bytes via `utf8`).

```ts
// src/paseto/claims.ts
import { ClaimError } from '../errors.js';
export interface Validate { exp?: boolean; nbf?: boolean; iss?: string; aud?: string; sub?: string; clockToleranceSec?: number }
export function validateClaims(payload: Record<string, unknown>, v: Validate, now = Date.now()): void {
  const tol = (v.clockToleranceSec ?? 0) * 1000;
  if (v.exp && typeof payload.exp === 'string') { if (now - tol > Date.parse(payload.exp)) throw new ClaimError('exp', 'token expired'); }
  if (v.nbf && typeof payload.nbf === 'string') { if (now + tol < Date.parse(payload.nbf)) throw new ClaimError('nbf', 'token not yet valid'); }
  for (const c of ['iss', 'aud', 'sub'] as const) { if (v[c] !== undefined && payload[c] !== v[c]) throw new ClaimError(c, `${c} mismatch`); }
}
```

- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: claims validation + high-level encode/decode"`

---

### Task 9: Public surface wiring

**Files:**
- Modify: `src/index.ts`
- Test: `test/api.test.ts`

**Interfaces:**
- Produces: barrel export of `encrypt, decrypt, sign, verify, generateLocalKey, generateKeyPair, LocalKey, SecretKey, PublicKey`, all error classes.

- [ ] **Step 1: Failing test** — import each named export from `../src/index.js`; assert `typeof === 'function'`/defined.
- [ ] **Step 2: Run → FAIL**.
- [ ] **Step 3: Implement** re-exports in `src/index.ts`.
- [ ] **Step 4: Run → PASS + `npm run build` succeeds**. **Step 5: Commit** — `git commit -am "feat: public API barrel"`

---

### Task 10: PASERK serialize — local / public / secret

**Files:**
- Create: `src/paserk/serialize.ts`, `test/vectors/paserk-k4.vectors.json` (types: `k4.local`, `k4.public`, `k4.secret`), `test/paserk/serialize.test.ts`

**Interfaces:**
- Produces: `toPaserk(key: LocalKey | PublicKey | SecretKey): string`; `fromPaserk(s: string): LocalKey | PublicKey | SecretKey`.
- `k4.local.<b64u(bytes)>`, `k4.public.<b64u(bytes)>`, `k4.secret.<b64u(bytes)>`.

- [ ] **Step 1: Fetch official PASERK type vectors** (`k4.local`, `k4.public`, `k4.secret`) from `paseto-standard/paserk` → commit JSON.
- [ ] **Step 2: Failing test** — for each vector: `toPaserk(new XKey(hb(v.key))) === v.paserk` and `fromPaserk(v.paserk).bytes === hb(v.key)`.
- [ ] **Step 3: Implement** header-prefix + b64url mapping; reject unknown headers with `PaserkError`.
- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: PASERK serialize local/public/secret (vectors green)"`

---

### Task 11: PASERK ids — lid / pid / sid

**Files:**
- Create: `src/paserk/id.ts`, add id cases to `test/vectors/paserk-k4.vectors.json`, `test/paserk/id.test.ts`

**Interfaces:**
- Produces: `keyId(key): string` → `k4.lid.` / `k4.pid.` / `k4.sid.` + `b64u(BLAKE2b(dkLen=33, msg = header || toPaserk(key)))`.

- [ ] **Step 1: Fetch official `k4.lid`/`k4.pid`/`k4.sid` vectors**, commit.
- [ ] **Step 2: Failing test** — `keyId(new XKey(hb(v.key))) === v.paserk` per vector.
- [ ] **Step 3: Implement** per PASERK ID operation (BLAKE2b of the id-header concatenated with the underlying PASERK string; confirm exact `dkLen`/prefix against vectors).
- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: PASERK key ids (vectors green)"`

---

### Task 12: PASERK wrap — local-wrap.pie / secret-wrap.pie

**Files:**
- Create: `src/paserk/wrap.ts`, add wrap vectors to `test/vectors/paserk-k4.vectors.json`, `test/paserk/wrap.test.ts`

**Interfaces:**
- Produces: `wrapKey(key: LocalKey | SecretKey, wrappingKey: LocalKey): string`; `unwrapKey(paserk: string, wrappingKey: LocalKey): LocalKey | SecretKey`.
- `.pie` construction (per PASERK operations): random nonce → derive auth+enc keys from wrapping key via BLAKE2b domain-separated tags → XChaCha20 encrypt the key bytes → BLAKE2b auth tag over header+nonce+ciphertext → `k4.local-wrap.pie.<b64u(tag||nonce||ct)>`.

- [ ] **Step 1: Fetch official wrap vectors** (fixed nonce provided), commit.
- [ ] **Step 2: Failing test** — vector-driven wrap (inject nonce) equals expected; unwrap roundtrips; tampered input → `PaserkError`.
- [ ] **Step 3: Implement** the `.pie` wrap/unwrap exactly per the PASERK operations doc, constant-time tag check.
- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: PASERK pie key wrapping (vectors green)"`

---

### Task 13: PASERK password wrap — local-pw / secret-pw

**Files:**
- Create: `src/paserk/pw.ts`, add pw vectors, `test/paserk/pw.test.ts`

**Interfaces:**
- Produces: `wrapWithPassword(key, password: string, opts?: { memlimit?; opslimit?; parallelism? }): string`; `unwrapWithPassword(paserk, password): LocalKey | SecretKey`.
- v4 uses **Argon2id** (`@noble/hashes/argon2`) to derive the wrapping key from the password + stored params/salt, then a pie-style wrap.

- [ ] **Step 1: Fetch official pw vectors** (salt + argon2 params fixed), commit.
- [ ] **Step 2: Failing test** — vector-driven derivation reproduces expected PASERK; roundtrip with a chosen password; wrong password → `PaserkError`.
- [ ] **Step 3: Implement** per PASERK `local-pw`/`secret-pw` operation (Argon2id params serialized into the output; confirm byte layout against vectors).
- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: PASERK password wrapping via argon2id (vectors green)"`

---

### Task 14: PASERK seal

**Files:**
- Create: `src/paserk/seal.ts`, add seal vectors, `test/paserk/seal.test.ts`

**Interfaces:**
- Produces: `sealKey(key: LocalKey, recipientPublic: PublicKey): string`; `unsealKey(paserk: string, recipientSecret: SecretKey): LocalKey`.
- v4 seal (per PASERK operations): X25519 (convert Ed25519 keys to X25519) ephemeral ECDH → BLAKE2b-derived enc+auth keys → XChaCha20 wrap the local key → auth tag → `k4.seal.<...>`.

- [ ] **Step 1: Fetch official seal vectors** (fixed ephemeral), commit.
- [ ] **Step 2: Failing test** — unseal(vector) → expected local key; seal→unseal roundtrip with a generated recipient keypair; tamper → `PaserkError`.
- [ ] **Step 3: Implement** per operation doc (Ed25519→X25519 conversion via `@noble/curves` `edwardsToMontgomery`; confirm names against installed version).
- [ ] **Step 4: Run → PASS**. **Step 5: Commit** — `git commit -am "feat: PASERK seal via x25519 (vectors green)"`

---

### Task 15: PASERK surface + key convenience methods

**Files:**
- Modify: `src/keys/types.ts` (add `toPASERK()`, static `fromPASERK`), `src/index.ts`
- Test: `test/paserk/api.test.ts`

**Interfaces:**
- Produces: `key.toPASERK()`, `LocalKey.fromPASERK/…`, and barrel exports of `wrapKey, unwrapKey, wrapWithPassword, unwrapWithPassword, sealKey, unsealKey, keyId, toPaserk, fromPaserk`.

- [ ] **Step 1: Failing test** — `LocalKey.fromPASERK(generateLocalKey().toPASERK())` roundtrips; each PASERK fn is exported.
- [ ] **Step 2: Run → FAIL**. **Step 3: Implement** (delegate methods to `paserk/*`). **Step 4: Run → PASS + build**. **Step 5: Commit** — `git commit -am "feat: PASERK public surface + key methods"`

---

### Task 16: Release hardening — CI, docs, migration

**Files:**
- Create: `.github/workflows/ci.yml`, `README.md`, `SECURITY.md`, `CHANGELOG.md`, `LICENSE`

**Interfaces:**
- Produces: green CI across Node 18/20/22 + a browser env (happy-dom) + Deno + Bun smoke; README with quickstart, security notes, and a **panva → paseto-kit migration table**.

- [ ] **Step 1:** Write `LICENSE` (MIT, author "Tareq El-Ali"), `SECURITY.md`, `CHANGELOG.md` (0.1.0 entry).
- [ ] **Step 2:** Write `.github/workflows/ci.yml`: jobs = typecheck, `npm test` on Node 18/20/22; a Vitest run under `happy-dom`; `deno test`/`bun test` smoke importing the built ESM; publish job on tag with `--provenance`.
- [ ] **Step 3:** Write `README.md`: install, v4 local + public quickstart, PASERK examples (wrap/pw/seal/id), security notes (footer authenticated-not-encrypted; `-pw` vs `-wrap`), and the migration table from `panva/paseto` method names to `paseto-kit`.
- [ ] **Step 4:** Run full `npm test && npm run build && npm run typecheck` → all green.
- [ ] **Step 5: Commit** — `git commit -am "chore: CI matrix, docs, migration guide, license"`
- [ ] **Step 6 (manual, gated):** set `version` to `0.1.0`, resolve npm handle/scope, `npm publish` (requires user's npm auth — **do not automate**).

---

## Self-Review

**Spec coverage:** §3 scope → Tasks: utils (1–4), v4.local (6), v4.public (7), footer+assertion (6/7 params), claims (8), keys (5), all 11 PASERK types (10 local/public/secret, 11 lid/pid/sid, 12 local-wrap/secret-wrap, 13 local-pw/secret-pw, 14 seal), vectors (each crypto task), packaging (0/9/15/16). §6 error model → Task 4 hierarchy, used throughout. §7 testing → vector tasks + Task 16 matrix. §8 tooling → 0 + 16. §9 security → constant-time (Task 2/6/12), no custom crypto (@noble throughout), vector gate (16). **No gaps.**

**Placeholder scan:** Crypto Tasks 11–14 describe constructions at operation-level and defer exact byte layout to "confirm against vectors" — this is deliberate (the official vectors are the executable spec and the `@noble` v1.x API must be confirmed against the installed version), not a hand-wave; each has a concrete failing-test-first vector gate. Pure/protocol Tasks 0–10 contain full code.

**Type consistency:** `LocalKey/SecretKey/PublicKey` (32/64/32 bytes) consistent across Tasks 5–15. `encryptRaw/decryptRaw/signRaw/verifyRaw` (Tasks 6–7) consumed by `encrypt/decrypt/sign/verify` (Task 8). `pae`, `b64uEncode/Decode`, `concat`, `utf8`, `timingSafeEqual`, `splitToken` signatures stable from Tasks 1–4 onward. `toPaserk/fromPaserk` (10) vs `keyId` (11) vs `wrapKey/unwrapKey` (12) — distinct names, no collision.

## Notes for the executor
- Fetch official vectors from `github.com/paseto-standard/test-vectors` (PASETO) and `github.com/paseto-standard/paserk` (PASERK, `tests/` dir). Commit the JSON so CI is hermetic.
- Confirm every `@noble/*` import path + method name against the versions actually installed by Task 0 before trusting the sketched calls; the vector assertions are the backstop.
- v3 protocol is explicitly **phase 2** — do not start it here.
