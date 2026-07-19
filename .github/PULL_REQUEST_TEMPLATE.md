<!-- Security fixes: consider private disclosure first — see SECURITY.md. -->

## What & why

Brief description of the change and the motivation.

## Checklist

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes (including the official PASETO/PASERK vectors)
- [ ] `npm run build` succeeds
- [ ] Added/updated tests for the change (vector-driven where it's crypto/PASERK)
- [ ] No new hand-rolled cryptography; primitives come from `@noble/*`
- [ ] `src/` stays runtime-agnostic (no `node:` imports, no `Buffer`)
- [ ] Updated docs / CHANGELOG if user-facing

## Notes

Anything reviewers should focus on.
