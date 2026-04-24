/**
 * Generates a cross-language interop fixture from casket-ts for Go interop tests.
 *
 * Exports ephemeral test keypairs (including private key material) so Go can
 * reconstruct the shared key and verify full TS→Go decrypt round-trips.
 * These keys are generated fresh each run and never committed.
 *
 * Usage:
 *   node gen-fixture.mjs <path-to-casket-ts-dist-esm-channel.js> [P-256|X25519]
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

// Storage that also exposes its internals for fixture export.
function makeStorage() {
  const store = new Map();
  return {
    get: async (k) => store.get(k) ?? null,
    put: async (k, v) => { store.set(k, v); },
    delete: async (k) => { store.delete(k); },
    dump: () => Object.fromEntries(store),
  };
}

const storA = makeStorage();
const storB = makeStorage();

const chA = await Channel.load('nexus-ts-a', storA, alg);
const chB = await Channel.load('nexus-ts-b', storB, alg);

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

// TS channelA encrypts — Go must be able to decrypt using A's DH priv + B's DH pub.
const encryptedByA = await pairedA.encryptBody(new TextEncoder().encode(plaintext), aad);

// TS channelB encrypts — Go must be able to decrypt using B's DH priv + A's DH pub.
const encryptedByB = await pairedB.encryptBody(new TextEncoder().encode(plaintext), aad);

// TS self-check.
const decByB = await pairedB.decryptBody(encryptedByA, aad);
const decByA = await pairedA.decryptBody(encryptedByB, aad);
if (new TextDecoder().decode(decByB) !== plaintext || new TextDecoder().decode(decByA) !== plaintext) {
  process.stderr.write('BUG: TS self-check decrypt failed\n');
  process.exit(1);
}

// Export DH private keys as raw bytes (base64url) so Go can reconstruct the shared key.
// These are ephemeral test keys — safe in a fixture, never committed.
function extractDhPrivRaw(store) {
  const jwkStr = store['casket:channel:dh_private_key'];
  if (!jwkStr) throw new Error('dh_private_key not found in storage');
  const jwk = JSON.parse(jwkStr);
  // For P-256: JWK 'd' is the scalar (32 bytes, base64url).
  // For X25519: JWK 'd' is the raw private scalar (32 bytes, base64url).
  // In both cases, 'd' is exactly what Go's ecdh.Curve.NewPrivateKey() wants.
  return jwk.d;
}

const dumpA = storA.dump();
const dumpB = storB.dump();

const fixture = {
  alg,
  channelA: {
    token: tokA,
    sigPubKey: chA.publicKeyB64u(),
    dhPubKey: chA.dhPublicKeyB64u(),
    dhPrivKeyRaw: extractDhPrivRaw(dumpA),  // base64url raw DH private scalar
  },
  channelB: {
    token: tokB,
    sigPubKey: chB.publicKeyB64u(),
    dhPubKey: chB.dhPublicKeyB64u(),
    dhPrivKeyRaw: extractDhPrivRaw(dumpB),
  },
  expectedPathId: pairedA.pathId(),
  encryptedByA,   // TS channelA encrypted → Go (acting as B) must decrypt
  encryptedByB,   // TS channelB encrypted → Go (acting as A) must decrypt
  aad: Buffer.from(aad).toString('base64url'),
  plaintext,
};

process.stdout.write(JSON.stringify(fixture, null, 2) + '\n');
