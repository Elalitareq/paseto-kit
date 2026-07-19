import { expect, test } from 'vitest';
import { splitToken } from '../../src/util/validate.js';
import { FormatError } from '../../src/errors.js';

test('splits header/body/footer', () => {
  const r = splitToken('v4.local.aGVsbG8.d29ybGQ');
  expect(r.header).toBe('v4.local.');
  expect(r.purpose).toBe('local');
  expect(new TextDecoder().decode(r.footer)).toBe('world');
});

test('no footer', () => {
  const r = splitToken('v4.public.aGVsbG8');
  expect(r.header).toBe('v4.public.');
  expect(r.footer).toEqual(new Uint8Array());
});

test('rejects malformed', () => {
  expect(() => splitToken('nope')).toThrow(FormatError);
  expect(() => splitToken('v2.local.aGVsbG8')).toThrow(FormatError);
  expect(() => splitToken('v4.bogus.aGVsbG8')).toThrow(FormatError);
});
