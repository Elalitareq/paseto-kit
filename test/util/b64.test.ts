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

test('rejects invalid characters', () => {
  expect(() => b64uDecode('aGVs*G8')).toThrow();
  expect(() => b64uDecode('aa=a')).toThrow(); // '=' padding not allowed
});

test('rejects non-canonical trailing bits', () => {
  // 2-char group → 1 byte; the 2nd char's low 4 bits must be zero.
  expect(() => b64uDecode('ab')).toThrow(); // 'b' (26) low nibble != 0
  expect(() => b64uDecode('aA')).not.toThrow(); // 'A' (0) canonical
  // 3-char group → 2 bytes; the 3rd char's low 2 bits must be zero.
  expect(() => b64uDecode('aaB')).toThrow(); // 'B' (1) low 2 bits != 0
  expect(() => b64uDecode('aaA')).not.toThrow(); // 'A' (0) canonical
});

test('rejects impossible length (n % 4 === 1)', () => {
  expect(() => b64uDecode('aaaaa')).toThrow();
});
