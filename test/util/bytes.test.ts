import { expect, test } from 'vitest';
import { concat, utf8, fromUtf8, timingSafeEqual } from '../../src/util/bytes.js';

test('concat', () => {
  expect(concat(new Uint8Array([1]), new Uint8Array([2, 3]))).toEqual(new Uint8Array([1, 2, 3]));
  expect(concat()).toEqual(new Uint8Array());
});

test('utf8 roundtrip', () => {
  expect(fromUtf8(utf8('héllo'))).toBe('héllo');
});

test('timingSafeEqual', () => {
  expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
  expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
  expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
});
