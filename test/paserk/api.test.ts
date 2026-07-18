import { expect, test } from 'vitest';
import * as api from '../../src/index.js';
import {
  toPaserk,
  fromPaserk,
  keyId,
  wrapKey,
  unwrapKey,
  sealKey,
  unsealKey,
  generateLocalKey,
  generateKeyPair,
  LocalKey,
} from '../../src/index.js';

test('all PASERK functions are exported', () => {
  for (const name of [
    'toPaserk',
    'fromPaserk',
    'keyId',
    'wrapKey',
    'unwrapKey',
    'wrapWithPassword',
    'unwrapWithPassword',
    'sealKey',
    'unsealKey',
  ]) {
    expect(typeof (api as Record<string, unknown>)[name]).toBe('function');
  }
});

test('serialize roundtrip via public surface', () => {
  const k = generateLocalKey();
  const restored = fromPaserk(toPaserk(k));
  expect(restored).toBeInstanceOf(LocalKey);
  expect((restored as LocalKey).bytes).toEqual(k.bytes);
});

test('key id is stable + typed', () => {
  const k = generateLocalKey();
  expect(keyId(k)).toBe(keyId(k));
  expect(keyId(k).startsWith('k4.lid.')).toBe(true);
});

test('wrap + seal roundtrip via public surface', () => {
  const wk = generateLocalKey();
  const ptk = generateLocalKey();
  expect((unwrapKey(wrapKey(ptk, wk), wk) as LocalKey).bytes).toEqual(ptk.bytes);

  const { secretKey, publicKey } = generateKeyPair();
  expect(unsealKey(sealKey(ptk, publicKey), secretKey).bytes).toEqual(ptk.bytes);
});
