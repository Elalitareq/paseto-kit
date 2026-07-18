import { expect, test } from 'vitest';
import { encrypt, decrypt, sign, verify } from '../../src/paseto/index.js';
import { generateLocalKey, generateKeyPair } from '../../src/keys/generate.js';
import { ClaimError, DecryptError } from '../../src/errors.js';

test('object payload roundtrip (local)', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { sub: 'abc', data: 1 });
  expect(decrypt(k, t).payload).toMatchObject({ sub: 'abc', data: 1 });
});

test('object payload roundtrip (public)', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const t = sign(secretKey, { role: 'admin' });
  expect(verify(publicKey, t).payload).toMatchObject({ role: 'admin' });
});

test('raw string payload roundtrip', () => {
  const k = generateLocalKey();
  const t = encrypt(k, 'plain text, not json');
  expect(decrypt(k, t).payload).toBe('plain text, not json');
});

test('footer roundtrip + mismatch rejected', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { a: 1 }, { footer: 'kid-1' });
  expect(new TextDecoder().decode(decrypt(k, t).footer)).toBe('kid-1');
  expect(() => decrypt(k, t, { footer: 'kid-2' })).toThrow(DecryptError);
});

test('expired token rejected only when validated', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { exp: new Date(Date.now() - 60_000).toISOString() });
  expect(() => decrypt(k, t, { validate: { exp: true } })).toThrow(ClaimError);
  expect(() => decrypt(k, t)).not.toThrow(); // no validation requested
});

test('not-yet-valid token rejected', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { nbf: new Date(Date.now() + 60_000).toISOString() });
  expect(() => decrypt(k, t, { validate: { nbf: true } })).toThrow(ClaimError);
});

test('clock tolerance permits slightly-expired token', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { exp: new Date(Date.now() - 5_000).toISOString() });
  expect(() => decrypt(k, t, { validate: { exp: true, clockToleranceSec: 30 } })).not.toThrow();
});

test('audience / issuer mismatch rejected', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { aud: 'a', iss: 'me' });
  expect(() => decrypt(k, t, { validate: { aud: 'b' } })).toThrow(ClaimError);
  expect(() => decrypt(k, t, { validate: { iss: 'me', aud: 'a' } })).not.toThrow();
});

test('implicit assertion must match', () => {
  const k = generateLocalKey();
  const t = encrypt(k, { a: 1 }, { assertion: 'tenant-42' });
  expect(decrypt(k, t, { assertion: 'tenant-42' }).payload).toMatchObject({ a: 1 });
  expect(() => decrypt(k, t, { assertion: 'tenant-99' })).toThrow(DecryptError);
});
