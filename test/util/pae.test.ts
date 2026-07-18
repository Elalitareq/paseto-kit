import { expect, test } from 'vitest';
import { pae } from '../../src/util/pae.js';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const u = (s: string) => new TextEncoder().encode(s);

// Official PAE known-answer values from the PASETO spec (Common/PAE).
test('PAE([]) = LE64(0)', () => {
  expect(hex(pae([]))).toBe('0000000000000000');
});

test('PAE([""])', () => {
  expect(hex(pae([new Uint8Array()]))).toBe('0100000000000000' + '0000000000000000');
});

test('PAE(["test"])', () => {
  expect(hex(pae([u('test')]))).toBe('0100000000000000' + '0400000000000000' + '74657374');
});

test('PAE(["", ""])', () => {
  expect(hex(pae([new Uint8Array(), new Uint8Array()]))).toBe(
    '0200000000000000' + '0000000000000000' + '0000000000000000',
  );
});
