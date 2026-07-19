import { expect, test } from 'vitest';

// Raw-import every source file (Vite feature — no node:fs needed).
// `import.meta.glob` is provided by Vite/Vitest; TS doesn't ship its type.
const glob = (import.meta as unknown as {
  glob: (pattern: string, opts: Record<string, unknown>) => Record<string, string>;
}).glob;
const files = glob('../src/**/*.ts', { query: '?raw', import: 'default', eager: true });

// The runtime-agnostic guarantee, enforced statically: src/ must not depend on
// any Node built-in or global. This is what lets one build run in Node, Deno,
// Bun, browsers, and edge runtimes unchanged.
test('src imports no Node built-ins', () => {
  const bad: string[] = [];
  for (const [path, src] of Object.entries(files)) {
    if (/from\s+['"]node:/.test(src) || /require\(\s*['"]node:/.test(src)) {
      bad.push(`${path} imports a node: module`);
    }
  }
  expect(bad).toEqual([]);
});

test('src uses no Node-only globals (Buffer / process / __dirname)', () => {
  const bad: string[] = [];
  for (const [path, src] of Object.entries(files)) {
    for (const g of ['Buffer', 'process', '__dirname', '__filename']) {
      if (new RegExp(`\\b${g}\\b`).test(src)) bad.push(`${path} references ${g}`);
    }
  }
  expect(bad).toEqual([]);
});

test('found the source files', () => {
  expect(Object.keys(files).length).toBeGreaterThan(15);
});
