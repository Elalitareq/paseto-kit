# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab), or by email to the
maintainer. Do **not** open a public issue for security reports.

You can expect an initial acknowledgement within a few days. Please include a
description, affected versions, and a reproduction if possible.

## Scope & posture

- `paseto-kit` implements PASETO v4 and PASERK by assembling audited
  [`@noble`](https://paulmillr.com/noble/) primitives — it contains no bespoke
  cryptographic implementations.
- Correctness is enforced against the official PASETO and PASERK test vectors in CI.
- The library has **not** yet undergone an independent third-party security audit.

## Handling notes for users

- Footers are authenticated but **not** encrypted. Never place secrets in a footer.
- Prefer `-wrap` for machine-held wrapping keys and `-pw` for password-derived protection.
- Keep `@noble/*` dependencies up to date.
