import { expect, test } from 'vitest';
import official from '../vectors/v3.official.json';
import { signRaw, verifyRaw } from '../../src/paseto/v3-public.js';
import { V3SecretKey, V3PublicKey, generateV3KeyPair } from '../../src/keys/v3.js';
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

const pub = vectors.tests.filter((t) => t.name.startsWith('3-S-') && !t['expect-fail']);

// ECDSA in the reference vectors uses non-deterministic k, so the signature bytes
// are not reproducible — we verify the vector token, and round-trip our own signer.
for (const v of pub) {
  test(`v3.public verify matches vector: ${v.name}`, () => {
    const { message } = verifyRaw(
      new V3PublicKey(hb(v['public-key'])),
      v.token,
      u(v.footer ?? ''),
      u(v['implicit-assertion'] ?? ''),
    );
    expect(new TextDecoder().decode(message)).toBe(v.payload);
  });

  test(`v3.public sign→verify round-trips the vector key: ${v.name}`, () => {
    const sk = new V3SecretKey(hb(v['secret-key']));
    const pk = new V3PublicKey(hb(v['public-key']));
    const token = signRaw(sk, u(v.payload), u(v.footer ?? ''), u(v['implicit-assertion'] ?? ''));
    const { message } = verifyRaw(pk, token, u(v.footer ?? ''), u(v['implicit-assertion'] ?? ''));
    expect(new TextDecoder().decode(message)).toBe(v.payload);
  });
}

test('tampered v3.public signature rejected', () => {
  const { secretKey, publicKey } = generateV3KeyPair();
  const token = signRaw(secretKey, u('{"a":1}'));
  const bad = token.slice(0, -2) + (token.endsWith('a') ? 'b' : 'a');
  expect(() => verifyRaw(publicKey, bad)).toThrow(VerifyError);
});
