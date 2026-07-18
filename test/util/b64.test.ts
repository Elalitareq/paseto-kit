import { expect, test } from 'vitest';
import { b64uEncode, b64uDecode } from '../../src/util/b64.js';

test('roundtrip + known vector', () => {
  const bytes = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
  expect(b64uEncode(bytes)).toBe('aGVsbG8'); // no padding
  expect(b64uDecode('aGVsbG8')).toEqual(bytes);
});

test('no padding, url-safe chars', () => {
  const b = new Uint8Array([0xff, 0xff, 0xfe]);
  const s = b64uEncode(b);
  expect(s).not.toContain('=');
  expect(s).not.toMatch(/[+/]/);
  expect(b64uDecode(s)).toEqual(b);
});

test('empty', () => {
  expect(b64uEncode(new Uint8Array())).toBe('');
  expect(b64uDecode('')).toEqual(new Uint8Array());
});
