import { expect, test } from 'vitest';
import kLocalWrap from '../vectors/paserk/k4.local-wrap.pie.json';
import kSecretWrap from '../vectors/paserk/k4.secret-wrap.pie.json';
import { wrapKey, unwrapKey } from '../../src/paserk/wrap.js';
import { LocalKey, SecretKey } from '../../src/keys/types.js';
import { generateLocalKey } from '../../src/keys/generate.js';
import { PaserkError } from '../../src/errors.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  unwrapped: string;
  'wrapping-key': string;
  paserk: string;
}
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const cases = (v: unknown) => (v as { tests: Case[] }).tests.filter((t) => !t['expect-fail'] && t.unwrapped);

for (const v of cases(kLocalWrap)) {
  test(`k4.local-wrap.pie unwrap: ${v.name}`, () => {
    const out = unwrapKey(v.paserk, new LocalKey(hb(v['wrapping-key'])));
    expect(out).toBeInstanceOf(LocalKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
}
for (const v of cases(kSecretWrap)) {
  test(`k4.secret-wrap.pie unwrap: ${v.name}`, () => {
    const out = unwrapKey(v.paserk, new LocalKey(hb(v['wrapping-key'])));
    expect(out).toBeInstanceOf(SecretKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
}

test('wrap → unwrap roundtrip (local)', () => {
  const wk = generateLocalKey();
  const ptk = generateLocalKey();
  const wrapped = wrapKey(ptk, wk);
  expect(wrapped.startsWith('k4.local-wrap.pie.')).toBe(true);
  expect(unwrapKey(wrapped, wk).bytes).toEqual(ptk.bytes);
});

test('unwrap with wrong wrapping key rejected', () => {
  const wk = generateLocalKey();
  const wrapped = wrapKey(generateLocalKey(), wk);
  expect(() => unwrapKey(wrapped, generateLocalKey())).toThrow(PaserkError);
});
