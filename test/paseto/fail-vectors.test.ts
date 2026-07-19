import { expect, test } from 'vitest';
import v4official from '../vectors/v4.official.json';
import v3official from '../vectors/v3.official.json';
import { decrypt as v4decrypt, verify as v4verify } from '../../src/paseto/index.js';
import { v3 } from '../../src/paseto/v3.js';
import { LocalKey, PublicKey } from '../../src/keys/types.js';
import { V3LocalKey, V3PublicKey } from '../../src/keys/v3.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fails = (v: unknown): any[] => (v as any).tests.filter((t: any) => t['expect-fail']);
const hb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const u = (s: string) => new TextEncoder().encode(s);

// A compliant implementation MUST reject every expect-fail vector: tampered
// ciphertext/signature, wrong key, wrong version/purpose, non-canonical base64,
// or invalid structure. Each vector is fed to the decryptor for its FILE's
// intended version (e.g. a v3 token in the v4 file must be rejected by v4), and
// routed local vs public by which key field is present.
const cases = [
  ...fails(v4official).map((t) => ({ ...t, fileVersion: 4 })),
  ...fails(v3official).map((t) => ({ ...t, fileVersion: 3 })),
];
for (const v of cases) {
  test(`rejects expect-fail vector: ${v.name}`, () => {
    const isLocal = v.key !== undefined;
    const footer = u(v.footer ?? '');
    const assertion = u(v['implicit-assertion'] ?? '');
    expect(() => {
      if (v.fileVersion === 4 && isLocal) v4decrypt(new LocalKey(hb(v.key)), v.token, { footer, assertion });
      else if (v.fileVersion === 4) v4verify(new PublicKey(hb(v['public-key'])), v.token, { footer, assertion });
      else if (isLocal) v3.decrypt(new V3LocalKey(hb(v.key)), v.token, { footer, assertion });
      else v3.verify(new V3PublicKey(hb(v['public-key'])), v.token, { footer, assertion });
    }).toThrow();
  });
}
