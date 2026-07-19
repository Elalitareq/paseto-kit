import { expect, test } from 'vitest';
import official from '../vectors/v3.official.json';
import { _encrypt, decryptRaw } from '../../src/paseto/v3-local.js';
import { V3LocalKey } from '../../src/keys/v3.js';
import { DecryptError } from '../../src/errors.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  key: string;
  nonce: string;
  token: string;
  payload: string;
  footer: string;
  'implicit-assertion': string;
}
const vectors = official as unknown as { tests: Case[] };
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const u = (s: string) => new TextEncoder().encode(s);

const local = vectors.tests.filter((t) => t.name.startsWith('3-E-') && !t['expect-fail']);

for (const v of local) {
  test(`v3.local encrypt matches vector: ${v.name}`, () => {
    const token = _encrypt(
      new V3LocalKey(hb(v.key)),
      u(v.payload),
      u(v.footer ?? ''),
      u(v['implicit-assertion'] ?? ''),
      hb(v.nonce),
    );
    expect(token).toBe(v.token);
  });

  test(`v3.local decrypt matches vector: ${v.name}`, () => {
    const { message } = decryptRaw(
      new V3LocalKey(hb(v.key)),
      v.token,
      u(v.footer ?? ''),
      u(v['implicit-assertion'] ?? ''),
    );
    expect(new TextDecoder().decode(message)).toBe(v.payload);
  });
}

test('tampered v3.local ciphertext rejected', () => {
  const key = new V3LocalKey(hb('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'));
  const token = _encrypt(key, u('hi'), new Uint8Array(), new Uint8Array(), new Uint8Array(32));
  const tampered = token.slice(0, -2) + (token.endsWith('a') ? 'b' : 'a');
  expect(() => decryptRaw(key, tampered)).toThrow(DecryptError);
});

test('at least 9 v3.local cases ran', () => {
  expect(local.length).toBeGreaterThanOrEqual(9);
});
