import { expect, test } from 'vitest';
import * as api from '../src/index.js';
import { encrypt, decrypt, sign, verify, generateLocalKey, generateKeyPair, LocalKey, PasetoError } from '../src/index.js';

test('public surface is exported', () => {
  for (const name of ['encrypt', 'decrypt', 'sign', 'verify', 'generateLocalKey', 'generateKeyPair']) {
    expect(typeof (api as Record<string, unknown>)[name]).toBe('function');
  }
  for (const name of ['LocalKey', 'SecretKey', 'PublicKey', 'PasetoError', 'ClaimError']) {
    expect((api as Record<string, unknown>)[name]).toBeDefined();
  }
});

test('end-to-end via public surface', () => {
  const k = generateLocalKey();
  expect(k).toBeInstanceOf(LocalKey);
  const t = encrypt(k, { hello: 'world' });
  expect(decrypt(k, t).payload).toMatchObject({ hello: 'world' });

  const { secretKey, publicKey } = generateKeyPair();
  expect(verify(publicKey, sign(secretKey, { ok: true })).payload).toMatchObject({ ok: true });
});

test('errors extend PasetoError', () => {
  const k = generateLocalKey();
  try {
    decrypt(k, 'v4.local.aaaa');
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(PasetoError);
  }
});
