import { expect, test } from 'vitest';
import official from '../vectors/v4.official.json';
import { signRaw, verifyRaw } from '../../src/paseto/v4-public.js';
import { SecretKey, PublicKey } from '../../src/keys/types.js';
import { VerifyError } from '../../src/errors.js';

interface Case {
  name: string;
  'expect-fail': boolean;
  'public-key': string;
  'secret-key': string;
  token: string;
  payload: string;
  footer: string;
  'implicit-assertion': string;
}
const vectors = official as unknown as { tests: Case[] };
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const u = (s: string) => new TextEncoder().encode(s);

const pub = vectors.tests.filter((t) => t.name.startsWith('4-S-') && !t['expect-fail']);

for (const v of pub) {
  test(`v4.public sign matches vector: ${v.name}`, () => {
    const token = signRaw(
      new SecretKey(hb(v['secret-key'])),
      u(v.payload),
      u(v.footer ?? ''),
      u(v['implicit-assertion'] ?? ''),
    );
    expect(token).toBe(v.token);
  });

  test(`v4.public verify matches vector: ${v.name}`, () => {
    const { message } = verifyRaw(
      new PublicKey(hb(v['public-key'])),
      v.token,
      u(v.footer ?? ''),
      u(v['implicit-assertion'] ?? ''),
    );
    expect(new TextDecoder().decode(message)).toBe(v.payload);
  });
}

test('tampered signature rejected', () => {
  const v = pub[0]!;
  const i = 12; // interior message char — keeps base64 canonical, forces a signature failure
  const bad = v.token.slice(0, i) + (v.token[i] === 'A' ? 'B' : 'A') + v.token.slice(i + 1);
  expect(() => verifyRaw(new PublicKey(hb(v['public-key'])), bad)).toThrow(VerifyError);
});

test('at least the expected number of public cases ran', () => {
  expect(pub.length).toBeGreaterThanOrEqual(3);
});
