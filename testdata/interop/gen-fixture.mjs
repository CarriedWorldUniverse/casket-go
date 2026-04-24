/**
 * Generates a cross-language interop fixture from casket-ts.
 *
 * Usage (from any directory):
 *   node gen-fixture.mjs <path-to-casket-ts-src-channel.js> [P-256|X25519]
 *
 * Example:
 *   node testdata/interop/gen-fixture.mjs \
 *       /absolute/path/to/casket-ts/src/channel.js P-256
 *
 * Output (stdout, JSON) is consumed by interop_test.go.
 */

import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const channelPath = process.argv[2];
const alg = process.argv[3] || 'P-256';

if (!channelPath) {
  process.stderr.write('Usage: node gen-fixture.mjs <path-to-channel.js> [P-256|X25519]\n');
  process.exit(1);
}

const { Channel } = await import(pathToFileURL(resolve(channelPath)).href);

function makeStorage() {
  const store = new Map();
  return {
    get: async (k) => store.get(k) ?? null,
    put: async (k, v) => { store.set(k, v); },
    delete: async (k) => { store.delete(k); },
  };
}

const chA = await Channel.load('nexus-ts-a', makeStorage(), alg);
const chB = await Channel.load('nexus-ts-b', makeStorage(), alg);

const tokA = chA.makePairingToken('https://ts-a.example.com');
const tokB = chB.makePairingToken('https://ts-b.example.com');

const pairedA = await chA.pair(tokB);
const pairedB = await chB.pair(tokA);

if (pairedA.pathId() !== pairedB.pathId()) {
  process.stderr.write('BUG: pathIds differ in TS fixture generation\n');
  process.exit(1);
}

const plaintext = 'Hello from casket-ts — interop check';
const aad = new TextEncoder().encode('test-aad-bytes');

const encryptedB64u = await pairedA.encryptBody(new TextEncoder().encode(plaintext), aad);

const decrypted = await pairedB.decryptBody(encryptedB64u, aad);
if (new TextDecoder().decode(decrypted) !== plaintext) {
  process.stderr.write('BUG: TS self-check decrypt failed\n');
  process.exit(1);
}

const fixture = {
  alg,
  channelA: {
    token: tokA,
    sigPubKey: chA.publicKeyB64u(),
    dhPubKey: chA.dhPublicKeyB64u(),
  },
  channelB: {
    token: tokB,
    sigPubKey: chB.publicKeyB64u(),
    dhPubKey: chB.dhPublicKeyB64u(),
  },
  expectedPathId: pairedA.pathId(),
  encryptedByA: encryptedB64u,
  aad: Buffer.from(aad).toString('base64url'),
  plaintext,
};

process.stdout.write(JSON.stringify(fixture, null, 2) + '\n');
