import { expect, test } from 'vitest';
import k4LocalWrap from '../vectors/paserk/k4.local-wrap.pie.json';
import k4SecretWrap from '../vectors/paserk/k4.secret-wrap.pie.json';
import k4LocalPw from '../vectors/paserk/k4.local-pw.json';
import k3LocalWrap from '../vectors/paserk/k3.local-wrap.pie.json';
import k3LocalPw from '../vectors/paserk/k3.local-pw.json';
import k4Local from '../vectors/paserk/k4.local.json';
import k3Local from '../vectors/paserk/k3.local.json';
import { unwrapKey } from '../../src/paserk/wrap.js';
import { unwrapWithPassword } from '../../src/paserk/pw.js';
import { fromPaserk } from '../../src/paserk/serialize.js';
import { unwrapKeyV3 } from '../../src/paserk/v3-wrap.js';
import { unwrapWithPasswordV3 } from '../../src/paserk/v3-pw.js';
import { fromPaserkV3 } from '../../src/paserk/v3-serialize.js';
import { LocalKey } from '../../src/keys/types.js';
import { V3LocalKey } from '../../src/keys/v3.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fails = (v: unknown): any[] => (v as any).tests.filter((t: any) => t['expect-fail']);
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));

// v4 wrapping / password fail vectors must reject.
for (const v of fails(k4LocalWrap))
  test(`rejects k4.local-wrap fail: ${v.name}`, () =>
    expect(() => unwrapKey(v.paserk, new LocalKey(hb(v['wrapping-key'])))).toThrow());
for (const v of fails(k4SecretWrap))
  test(`rejects k4.secret-wrap fail: ${v.name}`, () =>
    expect(() => unwrapKey(v.paserk, new LocalKey(hb(v['wrapping-key'])))).toThrow());
for (const v of fails(k4LocalPw))
  test(`rejects k4.local-pw fail: ${v.name}`, () =>
    expect(() => unwrapWithPassword(v.paserk, v.password)).toThrow());
for (const v of fails(k4Local))
  test(`rejects k4.local serialize fail: ${v.name}`, () => expect(() => fromPaserk(v.paserk)).toThrow());

// v3 wrapping / password fail vectors must reject.
for (const v of fails(k3LocalWrap))
  test(`rejects k3.local-wrap fail: ${v.name}`, () =>
    expect(() => unwrapKeyV3(v.paserk, new V3LocalKey(hb(v['wrapping-key'])))).toThrow());
for (const v of fails(k3LocalPw))
  test(`rejects k3.local-pw fail: ${v.name}`, () =>
    expect(() => unwrapWithPasswordV3(v.paserk, v.password)).toThrow());
for (const v of fails(k3Local))
  test(`rejects k3.local serialize fail: ${v.name}`, () => expect(() => fromPaserkV3(v.paserk)).toThrow());
