import { expect, test } from 'vitest';
import kSeal from '../vectors/paserk/k4.seal.json';
import { sealKey, unsealKey } from '../../src/paserk/seal.js';
import { LocalKey, PublicKey, SecretKey } from '../../src/keys/types.js';
import { generateKeyPair } from '../../src/keys/generate.js';
import { PaserkError } from '../../src/errors.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  'sealing-secret-key': string;
  'sealing-public-key': string;
  unsealed: string;
  paserk: string;
}
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const cases = (kSeal as unknown as { tests: Case[] }).tests.filter((t) => !t['expect-fail'] && t.unsealed);

for (const v of cases) {
  test(`k4.seal unseal: ${v.name}`, () => {
    const out = unsealKey(v.paserk, new SecretKey(hb(v['sealing-secret-key'])));
    expect(out).toBeInstanceOf(LocalKey);
    expect(out.bytes).toEqual(hb(v.unsealed));
  });
}

test('seal → unseal roundtrip', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const local = new LocalKey(hb('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'));
  const sealed = sealKey(local, publicKey);
  expect(sealed.startsWith('k4.seal.')).toBe(true);
  expect(unsealKey(sealed, secretKey).bytes).toEqual(local.bytes);
});

test('unseal with wrong recipient rejected', () => {
  const { publicKey } = generateKeyPair();
  const wrong = generateKeyPair().secretKey;
  const sealed = sealKey(new LocalKey(new Uint8Array(32)), publicKey);
  expect(() => unsealKey(sealed, wrong)).toThrow(PaserkError);
});

test('at least 2 seal vectors ran', () => {
  expect(cases.length).toBeGreaterThanOrEqual(2);
});
