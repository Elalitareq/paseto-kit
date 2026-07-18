import { expect, test } from 'vitest';
import kLocalPw from '../vectors/paserk/k4.local-pw.json';
import kSecretPw from '../vectors/paserk/k4.secret-pw.json';
import { wrapWithPassword, unwrapWithPassword } from '../../src/paserk/pw.js';
import { LocalKey, SecretKey } from '../../src/keys/types.js';
import { generateLocalKey } from '../../src/keys/generate.js';
import { PaserkError } from '../../src/errors.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  unwrapped: string;
  password: string;
  options: { memlimit: number; opslimit: number };
  paserk: string;
}
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const cases = (v: unknown) => (v as { tests: Case[] }).tests.filter((t) => !t['expect-fail'] && t.unwrapped);

for (const v of cases(kLocalPw)) {
  test(`k4.local-pw unwrap: ${v.name}`, () => {
    const out = unwrapWithPassword(v.paserk, v.password);
    expect(out).toBeInstanceOf(LocalKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
}
for (const v of cases(kSecretPw)) {
  test(`k4.secret-pw unwrap: ${v.name}`, () => {
    const out = unwrapWithPassword(v.paserk, v.password);
    expect(out).toBeInstanceOf(SecretKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
}

test('password wrap → unwrap roundtrip (fast params)', () => {
  const ptk = generateLocalKey();
  const wrapped = wrapWithPassword(ptk, 'hunter2', { memlimit: 1 << 20, opslimit: 2 });
  expect(wrapped.startsWith('k4.local-pw.')).toBe(true);
  expect((unwrapWithPassword(wrapped, 'hunter2') as LocalKey).bytes).toEqual(ptk.bytes);
});

test('wrong password rejected', () => {
  const wrapped = wrapWithPassword(generateLocalKey(), 'right', { memlimit: 1 << 20, opslimit: 2 });
  expect(() => unwrapWithPassword(wrapped, 'wrong')).toThrow(PaserkError);
});
