import { expect, test } from 'vitest';
import { generateLocalKey, generateKeyPair, randomBytes } from '../../src/keys/generate.js';

test('local key is 32 bytes', () => {
  expect(generateLocalKey().bytes.length).toBe(32);
});

test('keypair sizes + linkage', () => {
  const { secretKey, publicKey } = generateKeyPair();
  expect(secretKey.bytes.length).toBe(64);
  expect(publicKey.bytes.length).toBe(32);
  expect(secretKey.publicKeyBytes).toEqual(publicKey.bytes); // pub is tail of secret
});

test('randomBytes length + non-constant', () => {
  expect(randomBytes(16).length).toBe(16);
  expect(randomBytes(32)).not.toEqual(randomBytes(32));
});
