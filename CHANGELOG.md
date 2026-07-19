# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

### Added

- PASETO **v3** protocol (NIST): `v3.local` (HKDF-SHA384 → AES-256-CTR + HMAC-SHA384)
  and `v3.public` (ECDSA P-384 over SHA-384, with the compressed public key bound into
  the PAE). Exposed via the `v3` namespace; top-level `encrypt`/`decrypt`/`sign`/`verify`
  remain v4.
- **Full PASERK v3** (all 11 types): serialize, `lid`/`pid`/`sid` (SHA-384), `local-wrap`/
  `secret-wrap` (AES-CTR + HMAC-SHA384), `local-pw`/`secret-pw` (PBKDF2-SHA384), and
  `seal` (P-384 ECDH).
- Shared payload/claims marshalling extracted so v3 and v4 stay DRY.

### Notes

- v3.local + all v3 PASERK types are conformant against the official test vectors;
  v3.public is verified and round-tripped (ECDSA reference vectors use non-deterministic
  nonces, so signature bytes are not reproducible by design).

## [0.1.0]

### Added

- PASETO **v4.local** encrypt / decrypt (XChaCha20 + keyed BLAKE2b).
- PASETO **v4.public** sign / verify (Ed25519).
- Footer and implicit-assertion support on all token operations.
- Registered-claims validation: `exp`, `nbf`, `iss`, `aud`, `sub`, with clock tolerance.
- **Full PASERK v4**: `local` / `public` / `secret` serialization; `lid` / `pid` / `sid`
  key IDs; `local-wrap.pie` / `secret-wrap.pie`; `local-pw` / `secret-pw` (Argon2id);
  `seal` (X25519).
- Runtime-agnostic implementation over `@noble/*` (no `node:*`, no `Buffer`).
- Dual ESM / CJS build with emitted type declarations.
- Conformance test suites against the official PASETO and PASERK test vectors.
