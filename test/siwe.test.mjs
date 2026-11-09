// Regression tests for the 2026-11-09 security scan finding F1: the sign-in message parser must
// run in linear time on hostile input, refuse oversize input before parsing, follow EIP-4361
// strictly, and honour the signer's own Expiration Time and Not Before.
// SDK_BUILD=<dir> runs the same tests against another build (for example the previous release).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

const buildDir = process.env.SDK_BUILD || path.resolve(import.meta.dirname, '..', 'build');
const { parseSiweMessage, verifySiwe, extractEnvelope } = await import(pathToFileURL(path.join(buildDir, 'siwe.js')).href);
const { InMemoryNonceStore } = await import(pathToFileURL(path.join(buildDir, 'index.js')).href);

const DOMAIN = 'api.example.test';
const account = privateKeyToAccount(generatePrivateKey());
const iso = (ms) => new Date(ms).toISOString();

function message({ address = account.address, statement = 'Sign in to the example API.', version = '1', extra = [], order, nonce } = {}) {
  const fields = order ?? [
    'URI: https://api.example.test',
    `Version: ${version}`,
    'Chain ID: 1',
    `Nonce: ${nonce ?? Math.random().toString(36).slice(2, 12).padEnd(10, 'x')}`,
    `Issued At: ${iso(Date.now())}`,
    ...extra,
  ];
  return [`${DOMAIN} wants you to sign in with your Ethereum account:`, address, '', ...(statement ? [statement, ''] : []), ...fields].join('\n');
}

async function signIn(msg) {
  const signature = await account.signMessage({ message: msg });
  return verifySiwe({ message: msg, signature }, { nonceStore: new InMemoryNonceStore(), siweDomain: DOMAIN });
}

test('hostile first line is rejected in linear time (no backtracking)', () => {
  const hostile = 'a' + ' '.repeat(12000);
  const t0 = performance.now();
  assert.throws(() => parseSiweMessage(hostile));
  const ms = performance.now() - t0;
  assert.ok(ms < 50, `parse took ${ms.toFixed(1)} ms`);
});

test('an oversize message or header is refused before parsing', () => {
  const big = message({ statement: 'x'.repeat(5000) });
  assert.throws(() => parseSiweMessage(big), /too long/);
  const header = 'Wallet ' + 'A'.repeat(9000);
  assert.throws(() => extractEnvelope(header), /too long/);
});

test('a well-formed message signs in (with and without a statement, with resources)', async () => {
  assert.equal((await signIn(message())).wallet, account.address);
  assert.equal((await signIn(message({ statement: '' }))).wallet, account.address);
  const withResources = message({ extra: ['Request ID: r-1', 'Resources:', '- https://api.example.test/a', '- ipfs://bafy'] });
  assert.equal((await signIn(withResources)).wallet, account.address);
});

test('a passed Expiration Time is refused', async () => {
  const msg = message({ extra: [`Expiration Time: ${iso(Date.now() - 1000)}`] });
  await assert.rejects(signIn(msg), (e) => e.name === 'ExpiredSignatureError' || /expired/i.test(e.message));
});

test('a future Not Before is refused', async () => {
  const msg = message({ extra: [`Not Before: ${iso(Date.now() + 60_000)}`] });
  await assert.rejects(signIn(msg), (e) => e.name === 'FutureSignatureError' || /future/i.test(e.message));
});

test('Expiration Time in the future and Not Before in the past are accepted', async () => {
  const msg = message({ extra: [`Expiration Time: ${iso(Date.now() + 60_000)}`, `Not Before: ${iso(Date.now() - 60_000)}`] });
  assert.equal((await signIn(msg)).wallet, account.address);
});

test('a non-checksummed address, a wrong Version, and out-of-order fields are refused', async () => {
  await assert.rejects(signIn(message({ address: account.address.toLowerCase() })));
  await assert.rejects(signIn(message({ version: '2' })));
  const shuffled = [
    `Nonce: abcdefgh12`, 'URI: https://api.example.test', 'Version: 1', 'Chain ID: 1', `Issued At: ${iso(Date.now())}`,
  ];
  await assert.rejects(signIn(message({ order: shuffled })));
  const repeated = [
    'URI: https://api.example.test', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdefgh13', 'Nonce: abcdefgh14', `Issued At: ${iso(Date.now())}`,
  ];
  await assert.rejects(signIn(message({ order: repeated })));
});
