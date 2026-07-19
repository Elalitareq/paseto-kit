# Contributing to paseto-kit

Thanks for your interest in improving paseto-kit! This is a security library, so
correctness and caution matter more than speed.

## Ground rules

- **No hand-rolled cryptography.** paseto-kit assembles audited primitives from
  `@noble/*` per the PASETO/PASERK specs. New crypto must come from an audited
  primitive, not a bespoke implementation.
- **Stay runtime-agnostic.** `src/` must not import any `node:` module or use
  Node-only globals (`Buffer`, `process`, …). The purity test enforces this.
- **Conformance is the bar.** Changes to protocol/PASERK code must keep the
  official test-vector suites green, including the `expect-fail` cases.

## Development

```sh
npm install
npm test          # full suite (vitest), incl. official vectors
npm run typecheck # tsc --noEmit
npm run build     # tsup dual ESM/CJS
npm run bench     # optional: throughput numbers
```

- TypeScript strict; keep files small and single-purpose.
- Add tests with every behavioral change. For crypto/PASERK, prefer a test driven
  by an official vector over a hand-written expectation.

## Pull requests

1. Branch from `master`.
2. Make focused commits (`feat:` / `fix:` / `docs:` / `test:` …).
3. Ensure `npm run typecheck && npm test && npm run build` all pass.
4. Open the PR and fill in the template.

## Reporting security issues

Do **not** open a public issue for vulnerabilities — see [SECURITY.md](./SECURITY.md).
