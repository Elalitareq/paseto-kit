import { expect, test } from 'vitest';
import { v3 } from '../../src/paseto/v3.js';
import { decrypt as v4decrypt } from '../../src/paseto/index.js';
import { generateLocalKey } from '../../src/keys/generate.js';
import { ClaimError, DecryptError } from '../../src/errors.js';

test('v3 local object roundtrip', () => {
  const k = v3.generateLocalKey();
  const t = v3.encrypt(k, { sub: 'u1', n: 5 });
  expect(t.startsWith('v3.local.')).toBe(true);
  expect(v3.decrypt(k, t).payload).toMatchObject({ sub: 'u1', n: 5 });
});

test('v3 public object roundtrip', () => {
  const { secretKey, publicKey } = v3.generateKeyPair();
  const t = v3.sign(secretKey, { role: 'admin' });
  expect(t.startsWith('v3.public.')).toBe(true);
  expect(v3.verify(publicKey, t).payload).toMatchObject({ role: 'admin' });
});

test('v3 claims + footer', () => {
  const k = v3.generateLocalKey();
  const expired = v3.encrypt(k, { exp: new Date(Date.now() - 60_000).toISOString() });
  expect(() => v3.decrypt(k, expired, { validate: { exp: true } })).toThrow(ClaimError);

  const t = v3.encrypt(k, { a: 1 }, { footer: 'kid-9' });
  expect(new TextDecoder().decode(v3.decrypt(k, t).footer)).toBe('kid-9');
});

test('cross-version isolation: v4 decrypt rejects a v3 token', () => {
  const v3key = v3.generateLocalKey();
  const v3token = v3.encrypt(v3key, { x: 1 });
  // A v4 LocalKey cannot be used to read a v3 token (header mismatch).
  expect(() => v4decrypt(generateLocalKey(), v3token)).toThrow(DecryptError);
});
