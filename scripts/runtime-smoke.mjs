// Cross-runtime smoke test: exercises the built ESM bundle end-to-end.
// Run under Node, Deno, and Bun in CI to prove runtime-agnostic behavior.
import {
  generateLocalKey,
  encrypt,
  decrypt,
  generateKeyPair,
  sign,
  verify,
  toPaserk,
  fromPaserk,
} from '../dist/index.js';

const key = generateLocalKey();
const localToken = encrypt(key, { ok: true });
if (decrypt(key, localToken).payload.ok !== true) throw new Error('v4.local roundtrip failed');

const { secretKey, publicKey } = generateKeyPair();
if (verify(publicKey, sign(secretKey, { s: 1 })).payload.s !== 1) throw new Error('v4.public roundtrip failed');

if (fromPaserk(toPaserk(key)).bytes.length !== 32) throw new Error('PASERK roundtrip failed');

console.log('runtime smoke ok');
