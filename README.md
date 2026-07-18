# paseto-kit

**The complete, runtime-agnostic PASETO v4 + full PASERK library for JavaScript & TypeScript.**

A maintained successor to the archived [`panva/paseto`](https://github.com/panva/paseto).
Unlike other current libraries, `paseto-kit` ships **v4 tokens** *and* **full PASERK key
management** (wrapping, password-wrapping, sealing, key IDs) — built on audited
[`@noble`](https://paulmillr.com/noble/) primitives, running unmodified in Node, Deno,
Bun, browsers, and edge runtimes.

> ⚠️ **Pre-1.0.** The v4 protocol and all 11 PASERK types pass the official test vectors,
> but the library has not yet had an independent security audit. Review before production use.

## Why paseto-kit?

| | panva/paseto | paseto-ts | **paseto-kit** |
|---|:---:|:---:|:---:|
| Maintained | ❌ archived | ✅ | ✅ |
| v4 local + public | ✅ | ✅ | ✅ |
| PASERK key serialization | ✅ | partial | ✅ |
| PASERK **wrapping** (`local-wrap`/`secret-wrap`) | ✅ | ❌ | ✅ |
| PASERK **password** (`local-pw`/`secret-pw`) | ✅ | ❌ | ✅ |
| PASERK **seal** | ✅ | ❌ | ✅ |
| PASERK **key IDs** (`lid`/`pid`/`sid`) | ✅ | ❌ | ✅ |
| Runtime-agnostic (Node/Deno/Bun/browser/edge) | Node only | ✅ | ✅ |

## Install

```sh
npm install paseto-kit
```

Zero runtime dependencies beyond `@noble/ciphers`, `@noble/hashes`, `@noble/curves`.

## Quickstart

### v4.local — symmetric encryption

```ts
import { generateLocalKey, encrypt, decrypt } from 'paseto-kit';

const key = generateLocalKey();
const token = encrypt(key, { sub: 'user-123', exp: '2026-12-31T00:00:00Z' });

const { payload } = decrypt(key, token, { validate: { exp: true } });
// payload -> { sub: 'user-123', exp: '2026-12-31T00:00:00Z' }
```

### v4.public — asymmetric signatures

```ts
import { generateKeyPair, sign, verify } from 'paseto-kit';

const { secretKey, publicKey } = generateKeyPair();
const signed = sign(secretKey, { role: 'admin' });

const { payload } = verify(publicKey, signed);
// payload -> { role: 'admin' }
```

### Claims validation

```ts
decrypt(key, token, {
  validate: { exp: true, nbf: true, iss: 'my-api', aud: 'mobile', clockToleranceSec: 30 },
});
// throws ClaimError on any failed check
```

### Footers & implicit assertions

```ts
const token = encrypt(key, { a: 1 }, { footer: 'key-id-1', assertion: 'tenant-42' });
decrypt(key, token, { assertion: 'tenant-42' }); // assertion must match; footer is authenticated, not encrypted
```

## PASERK — key management

```ts
import {
  toPaserk, fromPaserk, keyId,
  wrapKey, unwrapKey,
  wrapWithPassword, unwrapWithPassword,
  sealKey, unsealKey,
  generateLocalKey, generateKeyPair,
} from 'paseto-kit';

const key = generateLocalKey();

// Serialize / deserialize
const s = toPaserk(key);           // "k4.local.…"
const back = fromPaserk(s);        // LocalKey

// Stable key identifier (safe to log)
keyId(key);                        // "k4.lid.…"

// Wrap a key with another symmetric key
const wrapped = wrapKey(key, generateLocalKey());   // "k4.local-wrap.pie.…"

// Wrap a key with a password (Argon2id)
const pw = wrapWithPassword(key, 'correct horse battery staple');  // "k4.local-pw.…"
const key2 = unwrapWithPassword(pw, 'correct horse battery staple');

// Seal a key for a recipient's public key (X25519)
const { secretKey, publicKey } = generateKeyPair();
const sealed = sealKey(key, publicKey);             // "k4.seal.…"
const key3 = unsealKey(sealed, secretKey);
```

## Migrating from panva/paseto

| panva/paseto (`V4`) | paseto-kit |
|---|---|
| `V4.encrypt(payload, key, { footer, assertion })` | `encrypt(key, payload, { footer, assertion })` |
| `V4.decrypt(token, key, { assertion })` | `decrypt(key, token, { assertion, validate })` |
| `V4.sign(payload, secretKey, { footer, assertion })` | `sign(secretKey, payload, { footer, assertion })` |
| `V4.verify(token, publicKey, { assertion })` | `verify(publicKey, token, { assertion, validate })` |
| `generateKeys('local' \| 'public')` | `generateLocalKey()` / `generateKeyPair()` |
| separate `paserk` package | built in (`toPaserk`, `wrapKey`, `sealKey`, …) |

Key differences: the key is the **first** argument; claim validation is **explicit** via
`{ validate }`; keys are typed (`LocalKey` / `SecretKey` / `PublicKey`).

## Security

- Built on audited `@noble/*` primitives — no hand-rolled crypto, only spec assembly.
- Constant-time authentication-tag and footer comparison.
- Conformance to the official PASETO and PASERK test vectors is enforced in CI.
- Footers are **authenticated but not encrypted** — never put secrets in a footer.
- `-pw` (password) is for human-memorable protection; `-wrap` is for machine keys.

See [SECURITY.md](./SECURITY.md) to report vulnerabilities.

## Roadmap

- **v1.0** — v4 (local + public) + full PASERK. *(current)*
- **Phase 2** — v3 (NIST: P-384 / AES-CTR / HMAC-SHA384) protocol + v3 PASERK.

## License

[MIT](./LICENSE) © Tareq El-Ali
