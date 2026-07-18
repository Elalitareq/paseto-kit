# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

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
