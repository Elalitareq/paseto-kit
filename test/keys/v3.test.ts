import { expect, test } from 'vitest';
import { generateV3LocalKey, generateV3KeyPair, V3LocalKey, V3SecretKey, V3PublicKey } from '../../src/keys/v3.js';

test('v3 local key is 32 bytes', () => {
  expect(generateV3LocalKey().bytes.length).toBe(32);
});

test('v3 keypair sizes + derived public matches', () => {
  const { secretKey, publicKey } = generateV3KeyPair();
  expect(secretKey.bytes.length).toBe(48);
  expect(publicKey.bytes.length).toBe(49);
  expect(secretKey.publicKeyBytes).toEqual(publicKey.bytes);
});

test('wrong sizes rejected', () => {
  expect(() => new V3LocalKey(new Uint8Array(31))).toThrow();
  expect(() => new V3SecretKey(new Uint8Array(32))).toThrow();
  expect(() => new V3PublicKey(new Uint8Array(48))).toThrow();
});
