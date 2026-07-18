import { expect, test } from 'vitest';
import { VERSION } from '../src/index.js';

test('module loads', () => {
  expect(VERSION).toBe('0.1.0');
});
