import { expect, test } from 'vitest';
import kLid from '../vectors/paserk/k4.lid.json';
import kPid from '../vectors/paserk/k4.pid.json';
import kSid from '../vectors/paserk/k4.sid.json';
import { keyId } from '../../src/paserk/id.js';
import { LocalKey, PublicKey, SecretKey } from '../../src/keys/types.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  key: string;
  paserk: string;
}
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const cases = (v: unknown) => (v as { tests: Case[] }).tests.filter((t) => !t['expect-fail'] && t.key);

for (const v of cases(kLid)) {
  test(`k4.lid: ${v.name}`, () => {
    expect(keyId(new LocalKey(hb(v.key)))).toBe(v.paserk);
  });
}
for (const v of cases(kPid)) {
  test(`k4.pid: ${v.name}`, () => {
    expect(keyId(new PublicKey(hb(v.key)))).toBe(v.paserk);
  });
}
for (const v of cases(kSid)) {
  test(`k4.sid: ${v.name}`, () => {
    expect(keyId(new SecretKey(hb(v.key)))).toBe(v.paserk);
  });
}
