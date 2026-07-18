import { expect, test } from 'vitest';
import kLocal from '../vectors/paserk/k4.local.json';
import kPublic from '../vectors/paserk/k4.public.json';
import kSecret from '../vectors/paserk/k4.secret.json';
import { toPaserk, fromPaserk } from '../../src/paserk/serialize.js';
import { LocalKey, PublicKey, SecretKey } from '../../src/keys/types.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  key: string;
  paserk: string;
}
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const cases = (v: unknown) => (v as { tests: Case[] }).tests.filter((t) => !t['expect-fail'] && t.key);

for (const v of cases(kLocal)) {
  test(`k4.local serialize: ${v.name}`, () => {
    const key = new LocalKey(hb(v.key));
    expect(toPaserk(key)).toBe(v.paserk);
    expect((fromPaserk(v.paserk) as LocalKey).bytes).toEqual(hb(v.key));
  });
}
for (const v of cases(kPublic)) {
  test(`k4.public serialize: ${v.name}`, () => {
    const key = new PublicKey(hb(v.key));
    expect(toPaserk(key)).toBe(v.paserk);
    expect((fromPaserk(v.paserk) as PublicKey).bytes).toEqual(hb(v.key));
  });
}
for (const v of cases(kSecret)) {
  test(`k4.secret serialize: ${v.name}`, () => {
    const key = new SecretKey(hb(v.key));
    expect(toPaserk(key)).toBe(v.paserk);
    expect((fromPaserk(v.paserk) as SecretKey).bytes).toEqual(hb(v.key));
  });
}
