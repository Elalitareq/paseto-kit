// Micro-benchmark for paseto-kit. Run: npm run build && node scripts/bench.mjs
import {
  generateLocalKey,
  generateKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
  v3,
} from '../dist/index.js';

function bench(name, fn, ms = 1000) {
  // Warm up.
  for (let i = 0; i < 50; i++) fn();
  let ops = 0;
  const start = performance.now();
  while (performance.now() - start < ms) {
    fn();
    ops++;
  }
  const elapsed = (performance.now() - start) / 1000;
  const perSec = Math.round(ops / elapsed);
  console.log(`  ${name.padEnd(26)} ${perSec.toLocaleString().padStart(10)} ops/sec`);
}

const payload = { sub: 'user-123', exp: '2099-01-01T00:00:00Z', scope: ['read', 'write'] };

console.log('\nv4 (Ed25519 / XChaCha20):');
const k4 = generateLocalKey();
const t4 = encrypt(k4, payload);
bench('v4.local encrypt', () => encrypt(k4, payload));
bench('v4.local decrypt', () => decrypt(k4, t4));
const kp4 = generateKeyPair();
const s4 = sign(kp4.secretKey, payload);
bench('v4.public sign', () => sign(kp4.secretKey, payload));
bench('v4.public verify', () => verify(kp4.publicKey, s4));

console.log('\nv3 (P-384 / AES-CTR):');
const k3 = v3.generateLocalKey();
const t3 = v3.encrypt(k3, payload);
bench('v3.local encrypt', () => v3.encrypt(k3, payload));
bench('v3.local decrypt', () => v3.decrypt(k3, t3));
const kp3 = v3.generateKeyPair();
const s3 = v3.sign(kp3.secretKey, payload);
bench('v3.public sign', () => v3.sign(kp3.secretKey, payload));
bench('v3.public verify', () => v3.verify(kp3.publicKey, s3));
console.log();
