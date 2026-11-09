// Regression tests: the attestation cache must be keyed on everything that decides the verdict
// (wallet, chain and contract address). Runs the real /v1/attest path against a local server
// that signs its own ES256 JWTs and passes only on Base.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { Access } from '../build/index.js';

const WALLET = '0x1111111111111111111111111111111111111111';
const CONTRACT = '0x2222222222222222222222222222222222222222';
const BASE_CHAIN_ID = 8453;

let server;
let baseUrl;
let privateKey;
let publicJwk;
let calls = [];
let failing = false;

before(async () => {
  const kp = await generateKeyPair('ES256');
  privateKey = kp.privateKey;
  publicJwk = { ...(await exportJWK(kp.publicKey)), kid: 'insumer-attest-v2', alg: 'ES256', use: 'sig' };

  server = http.createServer(async (req, res) => {
    if (req.url === '/.well-known/jwks.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ keys: [publicJwk] }));
    }
    if (req.url === '/v1/attest' && req.method === 'POST') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      const cond = body.conditions[0];
      calls.push({ chainId: cond.chainId, contractAddress: cond.contractAddress });
      if (failing) {
        res.writeHead(503);
        return res.end('down');
      }
      const pass = cond.chainId === BASE_CHAIN_ID;
      const jwt = await new SignJWT({ pass })
        .setProtectedHeader({ alg: 'ES256', kid: 'insumer-attest-v2' })
        .setIssuer('https://api.insumermodel.com')
        .setSubject(body.wallet)
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, data: { jwt } }));
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise(resolve => server.close(resolve)));

beforeEach(() => {
  calls = [];
  failing = false;
});

function makeAccess(cacheTtlMs = 2000) {
  return new Access({
    insumerApiKey: 'test-key',
    siweDomain: 'api.example.test',
    nonceStore: { setIfAbsent: () => true },
    cacheTtlMs,
    attestRetryCount: 0,
    attestBaseUrl: baseUrl,
    jwksUrl: `${baseUrl}/.well-known/jwks.json`,
    collections: {
      base: { address: CONTRACT, chain: 'base' },
      optimism: { address: CONTRACT, chain: 'optimism' },
    },
  });
}

test('same contract on two chains: each tier makes its own attest call and never shares a pass', async () => {
  const access = makeAccess();
  assert.equal(await access.hasValidPass('base', WALLET), true);
  assert.equal(await access.hasValidPass('optimism', WALLET), false, 'Base holder must not pass the Optimism tier');
  assert.deepEqual(calls.map(c => c.chainId), [8453, 10]);
});

test('same contract on two chains, Optimism checked first: a fail is not reused for Base', async () => {
  const access = makeAccess();
  assert.equal(await access.hasValidPass('optimism', WALLET), false);
  assert.equal(await access.hasValidPass('base', WALLET), true);
  assert.deepEqual(calls.map(c => c.chainId), [10, 8453]);
});

test('wallet and contract casing do not split the cache', async () => {
  const access = makeAccess();
  assert.equal(await access.hasValidPass('base', WALLET), true);
  assert.equal(await access.hasValidPass('base', WALLET.toUpperCase().replace('0X', '0x')), true);
  assert.equal(calls.length, 1);
});

test('the same tier repeated still hits the cache', async () => {
  const access = makeAccess();
  assert.equal(await access.hasValidPass('base', WALLET), true);
  assert.equal(await access.hasValidPass('base', WALLET), true);
  assert.equal(await access.hasValidPass('optimism', WALLET), false);
  assert.equal(await access.hasValidPass('optimism', WALLET), false);
  assert.equal(calls.length, 2);
});

test('stale fallback is keyed per chain too', async () => {
  const access = makeAccess(100);
  assert.equal(await access.hasValidPass('base', WALLET), true);
  await new Promise(resolve => setTimeout(resolve, 150)); // let the fresh entry expire
  failing = true;
  // Base: its own stale verdict is served inside the grace window.
  assert.equal(await access.hasValidPass('base', WALLET), true);
  // Optimism: no verdict of its own, so the outage surfaces instead of Base's stale pass.
  await assert.rejects(access.hasValidPass('optimism', WALLET), { name: 'AttestUnreachableError' });
});

test('localMode.mockAttest gets the chain and is cached per chain', async () => {
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  try {
    const seen = [];
    const access = new Access({
      insumerApiKey: 'test-key',
      siweDomain: 'api.example.test',
      nonceStore: { setIfAbsent: () => true },
      localMode: {
        mockAttest: (wallet, address, chain) => {
          seen.push(chain);
          return chain === 'base';
        },
      },
      collections: {
        base: { address: CONTRACT, chain: 'base' },
        optimism: { address: CONTRACT, chain: 'optimism' },
      },
    });
    assert.equal(await access.hasValidPass('base', WALLET), true);
    assert.equal(await access.hasValidPass('optimism', WALLET), false);
    assert.equal(await access.hasValidPass('base', WALLET), true);
    assert.deepEqual(seen, ['base', 'optimism']);
  } finally {
    process.env.NODE_ENV = prev;
  }
});
