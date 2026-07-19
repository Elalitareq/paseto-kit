import { expect, test } from 'vitest';
import kLocal from '../vectors/paserk/k3.local.json';
import kPublic from '../vectors/paserk/k3.public.json';
import kSecret from '../vectors/paserk/k3.secret.json';
import kLid from '../vectors/paserk/k3.lid.json';
import kPid from '../vectors/paserk/k3.pid.json';
import kSid from '../vectors/paserk/k3.sid.json';
import kLocalWrap from '../vectors/paserk/k3.local-wrap.pie.json';
import kSecretWrap from '../vectors/paserk/k3.secret-wrap.pie.json';
import kLocalPw from '../vectors/paserk/k3.local-pw.json';
import kSecretPw from '../vectors/paserk/k3.secret-pw.json';
import kSeal from '../vectors/paserk/k3.seal.json';
import { toPaserkV3, fromPaserkV3, keyIdV3 } from '../../src/paserk/v3-serialize.js';
import { wrapKeyV3, unwrapKeyV3 } from '../../src/paserk/v3-wrap.js';
import { wrapWithPasswordV3, unwrapWithPasswordV3 } from '../../src/paserk/v3-pw.js';
import { sealKeyV3, unsealKeyV3 } from '../../src/paserk/v3-seal.js';
import { V3LocalKey, V3PublicKey, V3SecretKey, generateV3KeyPair } from '../../src/keys/v3.js';

const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const good = (v: unknown, field: string): any[] => (v as any).tests.filter((t: any) => !t['expect-fail'] && t[field]);

// Extract the raw 48-byte P-384 scalar from a SEC1 EC PRIVATE KEY PEM.
function scalarFromPem(pem: string): Uint8Array {
  const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), (c) => c.charCodeAt(0));
  const i = der.findIndex((b, j) => b === 0x04 && der[j + 1] === 0x30);
  return der.slice(i + 2, i + 2 + 48);
}

// --- serialize ---
for (const v of good(kLocal, 'key'))
  test(`k3.local serialize: ${v.name}`, () => {
    expect(toPaserkV3(new V3LocalKey(hb(v.key)))).toBe(v.paserk);
    expect((fromPaserkV3(v.paserk) as V3LocalKey).bytes).toEqual(hb(v.key));
  });
for (const v of good(kPublic, 'key'))
  test(`k3.public serialize: ${v.name}`, () => {
    expect(toPaserkV3(new V3PublicKey(hb(v.key)))).toBe(v.paserk);
  });
for (const v of good(kSecret, 'key'))
  test(`k3.secret serialize: ${v.name}`, () => {
    expect(toPaserkV3(new V3SecretKey(hb(v.key)))).toBe(v.paserk);
  });

// --- ids ---
for (const v of good(kLid, 'key'))
  test(`k3.lid: ${v.name}`, () => expect(keyIdV3(new V3LocalKey(hb(v.key)))).toBe(v.paserk));
for (const v of good(kPid, 'key'))
  test(`k3.pid: ${v.name}`, () => expect(keyIdV3(new V3PublicKey(hb(v.key)))).toBe(v.paserk));
for (const v of good(kSid, 'key'))
  test(`k3.sid: ${v.name}`, () => expect(keyIdV3(new V3SecretKey(hb(v.key)))).toBe(v.paserk));

// --- wrap (pie) ---
for (const v of good(kLocalWrap, 'unwrapped'))
  test(`k3.local-wrap.pie unwrap: ${v.name}`, () => {
    const out = unwrapKeyV3(v.paserk, new V3LocalKey(hb(v['wrapping-key'])));
    expect(out).toBeInstanceOf(V3LocalKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
for (const v of good(kSecretWrap, 'unwrapped'))
  test(`k3.secret-wrap.pie unwrap: ${v.name}`, () => {
    const out = unwrapKeyV3(v.paserk, new V3LocalKey(hb(v['wrapping-key'])));
    expect(out).toBeInstanceOf(V3SecretKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
test('k3 wrap roundtrip', () => {
  const wk = new V3LocalKey(hb('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'));
  const ptk = new V3LocalKey(new Uint8Array(32).fill(7));
  expect((unwrapKeyV3(wrapKeyV3(ptk, wk), wk) as V3LocalKey).bytes).toEqual(ptk.bytes);
});

// --- pw (PBKDF2) — password field is used as a literal UTF-8 string ---
for (const v of good(kLocalPw, 'unwrapped'))
  test(`k3.local-pw unwrap: ${v.name}`, () => {
    const out = unwrapWithPasswordV3(v.paserk, v.password);
    expect(out).toBeInstanceOf(V3LocalKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
for (const v of good(kSecretPw, 'unwrapped'))
  test(`k3.secret-pw unwrap: ${v.name}`, () => {
    const out = unwrapWithPasswordV3(v.paserk, v.password);
    expect(out).toBeInstanceOf(V3SecretKey);
    expect(out.bytes).toEqual(hb(v.unwrapped));
  });
test('k3 pw roundtrip', () => {
  const ptk = new V3LocalKey(new Uint8Array(32).fill(9));
  const w = wrapWithPasswordV3(ptk, 'hunter2', { iterations: 1000 });
  expect((unwrapWithPasswordV3(w, 'hunter2') as V3LocalKey).bytes).toEqual(ptk.bytes);
});

// --- seal (P-384 ECDH) — vector keys are PEM ---
for (const v of good(kSeal, 'unsealed'))
  test(`k3.seal unseal: ${v.name}`, () => {
    const sk = new V3SecretKey(scalarFromPem(v['sealing-secret-key']));
    const out = unsealKeyV3(v.paserk, sk);
    expect(out.bytes).toEqual(hb(v.unsealed));
  });
test('k3 seal roundtrip', () => {
  const { secretKey, publicKey } = generateV3KeyPair();
  const ptk = new V3LocalKey(new Uint8Array(32).fill(3));
  expect(unsealKeyV3(sealKeyV3(ptk, publicKey), secretKey).bytes).toEqual(ptk.bytes);
});
