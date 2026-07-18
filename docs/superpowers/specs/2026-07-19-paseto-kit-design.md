# paseto-kit — Design Spec

**Date:** 2026-07-19
**Status:** Approved (design), pending implementation plan
**Author:** Tareq El-Ali (`<github-handle-TBD>` / npm `<npm-handle-TBD>`)
**License:** MIT

---

## 1. Purpose & value proposition

`paseto-kit` is the **complete, maintained, runtime-agnostic** PASETO v4 + full PASERK
library for JavaScript / TypeScript. It is positioned as the successor to the archived
`panva/paseto`.

**Day-one differentiator:** v4 tokens (`local` + `public`) **together with full PASERK
key management** (wrap / password / seal / key-ids) — which no *maintained* library
currently offers — implemented on audited `@noble/*` primitives and running unmodified
across Node, Deno, Bun, browsers, and edge/worker runtimes.

## 2. Motivation & competitive landscape (July 2026)

Deep-research finding: the "no JS PASETO" premise is **partly false**. The gap is
narrower than a void, but real.

| Library | Versions | Purposes | PASERK | Runtime | Status |
|---|---|---|---|---|---|
| `panva/paseto` | v1–v4 | local+public | full (separate pkg) | Node | **archived Mar 29 2025** |
| `paseto-ts` (auth70) | **v4 only** | local+public | **partial** — key *types* only, **no wrapping** | Node+browser | maintained (~98★) |
| `@mpoonuru/paseto` | v4 | **local only** | — | Node | recent |
| `paseto-wasm` / `paseto-browser` | v4 | varies | — | wrapper | niche |

**Unserved niche:** every *maintained* option is narrow — v4-only, mostly local-only,
and **none does full PASERK key-wrapping**. `paseto-ts` explicitly documents that it
"does not implement key wrapping or other PASERK features." That wrapping surface is the
wedge.

## 3. Scope

### In scope — v1.0
- **Utilities:** base64url (RFC 4648, no padding), PAE (pre-authentication encoding),
  byte helpers (concat, constant-time compare, utf8).
- **v4.local:** `encrypt` / `decrypt` (XChaCha20 + keyed-BLAKE2b split, 32-byte nonce,
  encrypt-then-MAC).
- **v4.public:** `sign` / `verify` (Ed25519 over PAE).
- **Footer** and **implicit assertion** support on all four operations.
- **Registered-claims validation:** `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`,
  configurable clock tolerance; opt-in per operation.
- **Keys:** generate / import / export as raw bytes and PASERK strings.
- **PASERK v4 — all 11 types:** `k4.local`, `k4.public`, `k4.secret`, `k4.lid`,
  `k4.pid`, `k4.sid`, `k4.local-wrap.pie`, `k4.secret-wrap.pie`, `k4.local-pw`,
  `k4.secret-pw`, `k4.seal`.
- **Conformance:** official PASETO v4 + PASERK test vectors as the correctness bar.
- **Packaging:** dual ESM/CJS, emitted `.d.ts`, tree-shakeable, zero runtime deps
  beyond `@noble/*`.

### Out of scope (later phases)
- **v3 (NIST: P-384 / AES-CTR / HMAC-SHA384)** → phase 2 (plus v3 PASERK).
- **v1 / v2** (deprecated by the PASETO project) → not planned.

## 4. Architecture

Small, single-purpose modules, layered in the spec's own dependency order (pure →
crypto → protocol → key-management). Pure layers are trivially and provably testable;
crypto layers rest on them.

```
src/
  util/
    b64.ts        # base64url encode/decode (no padding)
    pae.ts        # PAE: LE64 length-prefixed pre-auth encoding
    bytes.ts      # concat, constant-time compare, utf8 <-> bytes
    validate.ts   # header/length/purpose assertions
  keys/
    types.ts      # LocalKey / SecretKey / PublicKey typed wrappers
    generate.ts   # generateKeys(purpose)
    v4.ts         # v4 key material (32-byte local; ed25519 pair)
  paseto/
    v4-local.ts   # encrypt / decrypt
    v4-public.ts  # sign / verify
    claims.ts     # registered-claim validation + clock
    index.ts      # high-level encode/decode surface
  paserk/
    serialize.ts  # local/public/secret <-> k4.* strings
    id.ts         # lid / pid / sid  (BLAKE2b digest of the PASERK)
    wrap.ts       # local-wrap / secret-wrap  (pie: xchacha20 + blake2b)
    pw.ts         # local-pw / secret-pw       (argon2id KDF)
    seal.ts       # seal                        (x25519 + xchacha20 + blake2b)
    types.ts      # PASERK type parsing / typedefs
  index.ts        # public surface
```

**Crypto backbone (only runtime deps):**
- `@noble/ciphers` — XChaCha20
- `@noble/hashes` — BLAKE2b, Argon2id, PBKDF2
- `@noble/curves` — Ed25519, X25519
- Randomness: `globalThis.crypto.getRandomValues` (universal; no `node:crypto`, no `Buffer`)

Rationale: `@noble/*` is audited, dependency-free, and runs on plain `Uint8Array` in
every JS runtime — the single technical enabler for one build that is truly
platform-agnostic.

## 5. Public API (functional, typed)

```ts
// ---- tokens ----
encrypt(key: LocalKey, payload: Payload, opts?: EncodeOpts): string          // "v4.local.…"
decrypt(key: LocalKey, token: string, opts?: DecodeOpts): DecodeResult       // verifies MAC + claims
sign(key: SecretKey, payload: Payload, opts?: EncodeOpts): string            // "v4.public.…"
verify(key: PublicKey, token: string, opts?: DecodeOpts): DecodeResult

// Payload  = Record<string, unknown> (auto-JSON) | string | Uint8Array (raw)
// EncodeOpts = { footer?, assertion? }
// DecodeOpts = { assertion?, footer?,
//                validate?: { exp?, nbf?, iss?, aud?, sub?, clockToleranceSec? } }
// DecodeResult = { payload, footer }

// ---- keys + PASERK ----
generateKeys(purpose: 'local' | 'public'): LocalKey | { secretKey; publicKey }
key.toPASERK(): string
fromPASERK(paserk: string): LocalKey | PublicKey | SecretKey

wrapKey(key, wrappingKey): string            // k4.local-wrap.pie / k4.secret-wrap.pie
unwrapKey(paserk, wrappingKey): Key
wrapWithPassword(key, password, opts): string // k4.local-pw / k4.secret-pw (argon2id)
unwrapWithPassword(paserk, password): Key
sealKey(localKey, recipientPublicKey): string // k4.seal
unsealKey(paserk, recipientSecretKey): LocalKey
keyId(key): string                            // k4.lid / k4.pid / k4.sid
```

Ergonomics mirror JWT libraries where safe, but the API stays PASETO-correct
(purpose-scoped keys, no algorithm-confusion surface).

## 6. Error handling

Typed error hierarchy:

```
PasetoError (base)
├── FormatError     // malformed token / PASERK string, wrong header
├── DecryptError    // v4.local MAC mismatch  (generic, no oracle leak)
├── VerifyError     // v4.public signature failure
├── ClaimError      // failed registered-claim check; carries `.claim`
└── PaserkError     // key wrap/unwrap/seal/type failures
```

Rules:
- MAC and footer comparisons are **constant-time**.
- Crypto failures surface a generic decrypt/verify error — no padding-oracle or
  timing signal, no distinguishing "bad MAC" from "bad format" in a way that leaks.
- Error messages **never** contain key material or plaintext.
- Claim failures are specific (which claim, expected vs actual window) — safe to expose.

## 7. Testing strategy

- **Primary: TDD against official test vectors.** PASETO v4 and PASERK ship JSON
  known-answer vectors; these *are* the test suite. Conformance = provable correctness,
  not "probably right."
- **Property tests:** encrypt→decrypt and sign→verify roundtrips; any single-byte
  tamper (token, footer, nonce, tag, signature) must reject.
- **Negative tests:** wrong key, expired/not-yet-valid claims, wrong audience/issuer,
  wrong PASERK type, truncated input.
- **Runtime matrix:** Vitest on Node 18/20/22, a browser environment (happy-dom or real
  headless), plus Deno and Bun smoke suites in CI.
- Coverage gate on the crypto and PASERK modules.

## 8. Tooling & repo

- TypeScript strict; `tsup` dual ESM/CJS build with emitted types.
- Lint/format: eslint + prettier (or biome — decide in plan).
- **CI (GitHub Actions):** typecheck · lint · test matrix (Node×browser×Deno×Bun) ·
  test-vector conformance job · publish-on-tag with npm provenance.
- **Docs:** README (quickstart, security notes, **panva → paseto-kit migration table**),
  TypeDoc API reference.
- `SECURITY.md`, semver, `CHANGELOG.md`.

## 9. Security posture

- **No custom crypto.** Only spec assembly over audited `@noble/*` primitives.
- Constant-time MAC + footer comparison; CSPRNG via WebCrypto.
- Official-vector conformance is the correctness bar; no release without a green vector job.
- Docs must state the sharp edges: footers are authenticated **but not encrypted**;
  `-pw` vs `-wrap` guidance; never place secrets in a footer.

## 10. Build milestones (feed the implementation plan)

1. **Foundations:** `util/` (b64, pae, bytes, validate) + v4.local + v4.public + claims
   → PASETO v4 vectors green.
2. **PASERK core:** serialize (`local`/`public`/`secret`) + ids (`lid`/`pid`/`sid`).
3. **PASERK wrapping:** `wrap` (pie) + `pw` (argon2id) + `seal` (x25519) → PASERK vectors green.
4. **Release hardening:** runtime CI matrix, docs, migration guide → **1.0 publish**.

Phase 2 (post-1.0): **v3** protocol + v3 PASERK.

## 11. Open items

- Confirm GitHub org/username + npm handle (affects repo URL, package scope decision,
  author field). Package name settled: **`paseto-kit`** (unscoped, npm-available as of
  2026-07-19).
- Lint choice (eslint+prettier vs biome) — resolve during planning.
- Whether to also publish a thin `paserk` alias package pointing at the key-management
  surface (deferred; `paserk` is npm-available).
