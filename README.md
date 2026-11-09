# @skyemeta/access

[![npm](https://img.shields.io/npm/v/@skyemeta/access?color=0a1628&label=npm)](https://www.npmjs.com/package/@skyemeta/access) [![license](https://img.shields.io/github/license/skyemeta/skyemeta-access?color=0a1628)](LICENSE) [![release](https://img.shields.io/github/v/release/skyemeta/skyemeta-access?color=0a1628)](https://github.com/skyemeta/skyemeta-access/releases)

Add wallet-token authentication to your API without disturbing existing API-key customers.

```bash
npm install @skyemeta/access
```

## What it does

You run an API. Today your customers authenticate with an API key. But AI agents already have wallets, and they'd rather authenticate the same way they do everything else: by signing with their wallet.

`@skyemeta/access` is an either-or middleware:

- **`X-API-Key` header present** → your existing handler runs, untouched. Zero overhead.
- **`Authorization: Wallet ...` header present** → SDK verifies the SIWE signature, then asks InsumerAPI's `/v1/attest` whether the wallet still holds a valid token from the configured collection. Yes → request passes. No → 401.
- **Neither** → 401.

Your humans keep their keys. Your agents use the wallet they were going to carry anyway. Both work on the same routes.

## Quick start

```ts
import express from 'express';
import { Access } from '@skyemeta/access';

const access = new Access({
  insumerApiKey: process.env.INSUMER_API_KEY!,
  siweDomain: 'api.yourservice.com',
  collections: {
    default: { address: process.env.ACCESS_COLLECTION!, chain: 'base' },
  },
});

const app = express();

app.post(
  '/api/v1/whatever',
  access.requireValidPassOrApiKey(yourApiKeyMiddleware),
  handler,
);
```

The `Authorization: Wallet` header carries a standard EIP-4361 (Sign-In with Ethereum) message, read strictly: an EIP-55 checksummed address, `Version: 1`, fields in the EIP-4361 order, a message of at most 4 KB. Signatures are accepted for five minutes after `Issued At`, and sooner if the signer set `Expiration Time` or `Not Before`.

`siweDomain` is required and must match what your wallet clients put in their SIWE message domain field. Set it explicitly to the host your API serves SIWE messages for; don't rely on request-host inference behind reverse proxies.

Adopters also bring their own NFT/SBT collection; any ERC-721 works. We used [RNWY](https://rnwy.com): the trust intelligence layer for autonomous AI agents. RNWY's audited ERC-5192 factory on Base provides the soulbound issuance substrate for the InsumerAccess collection that backs InsumerAPI's own customers. Other options: [Thirdweb](https://thirdweb.com/), [Crossmint](https://www.crossmint.com/), or your own contract. See [Get an InsumerAPI key](#get-an-insumerapi-key) below for the key acquisition step.

## Get an InsumerAPI key

The SDK calls `/v1/attest` on your behalf, so you need an InsumerAPI key in `INSUMER_API_KEY`.

**Wallet-native (recommended for agent infrastructure):**

Send USDC or USDT to the InsumerAPI platform wallet on any supported chain, then POST the transaction hash. The sender wallet becomes the account's identity: no email, no signup form.

This SDK needs a string key in `INSUMER_API_KEY` to call `/v1/attest` from your server, so pass `"keyDelivery": "apiKey"` to receive one in the response. The endpoint's default is `"wallet"`, which delivers only the on-chain access pass with no string key; that path is for agents calling `/v1/attest` directly from their own runtime, not for the SDK use case.

```bash
curl -X POST https://api.insumermodel.com/v1/keys/buy \
  -H "Content-Type: application/json" \
  -d '{"txHash":"0x…","chainId":8453,"amount":5,"appName":"my-agent","keyDelivery":"apiKey"}'
```

Response (illustrative; key shown only once, store it):

```json
{
  "ok": true,
  "data": {
    "success": true,
    "key": "insr_live_...",
    "authMethod": "apiKey",
    "registeredWallet": "0x...",
    "totalCredits": 125
  }
}
```

On EVM payments the response also carries a `passMint` block indicating that a non-transferable Insumer Access pass was minted to the sender wallet. The wallet can then use signed-message auth (`Authorization: Wallet`) on `/v1/attest` and `/v1/credits/buy` directly, handy for top-ups from an agent runtime that prefers signing over carrying the key.

The envelope also includes `name`, `tier`, `dailyLimit`, `creditsAdded`, `usdcPaid`/`btcPaid`, `effectiveRate`, `chainName`, `authHint`, and a top-level `meta` block; see the OpenAPI spec for the full schema.

Solana (USDC/USDT), Bitcoin (native BTC), and Tron (USDT-TRC20) are also supported via the same endpoint; see [`/v1/keys/buy` in the OpenAPI spec](https://insumermodel.com/openapi.yaml) for the platform wallet addresses per chain and the full request schema. Minimum purchase is $5 (or BTC equivalent). Volume discount tiers: $5–$99 buys 25 credits/$1, $100–$499 buys 33 credits/$1, $500+ buys 50 credits/$1.

**Human signup (free tier): no signup, no dashboard, no password:**

If you're a human developer and want to try before paying, enter your email at [insumermodel.com](https://insumermodel.com/?utm_source=npm-skyemeta-access) and the form issues a free key (10 attestation credits, 100 requests/day, no card) inline in about 10 seconds. No account is created; the key is the credential.

**Already have a key?** Manage usage, top up, or upgrade at [insumermodel.com/developers/account/](https://insumermodel.com/developers/account/?utm_source=npm-skyemeta-access).

## What's in scope (v0.2.x)

The SDK's `requireValidPassOrApiKey` and `requireValidPass` middleware check **NFT ownership on EVM chains** (`nft_ownership` condition against any of the 31 EVM chains InsumerAPI supports: Ethereum, Base, Optimism, Arbitrum, Polygon, etc.). Non-EVM chains (Solana, XRPL, Bitcoin, Tron, Stellar, Sui) and richer condition types (`token_balance`, `eas_attestation`, `farcaster_id`, compound stacks) are reachable via direct calls to InsumerAPI's `/v1/attest`; the SDK's middleware stays focused on the common case.

## Post-quantum companion

InsumerAPI returns an ML-DSA-65 companion (`pqJwt`) beside the ES256 JWT on every attestation. The SDK checks it on every upstream call and reports it as `req.skyemetaAccess.pq` (`verified`, `refuted`, `absent`, or `unverifiable`, with a reason); it is undefined when the request was served from the cache or in local mode. A refuted companion always rejects the pass. An absent or unverifiable companion rejects only once your own `pqRequiredFrom` date (a config option, judged by this process's clock) has passed; leave it unset to report only. Install the optional peer `@noble/post-quantum` to verify companions; without it a present companion is reported `unverifiable`. Other config: `jwksUrl` and `attestBaseUrl` override the JWKS and API endpoints for testing. The companion is bound to the ES256 JWT by the full claim set: every claim in the two tokens must match, compared as parsed JSON, so a companion reported `verified` vouches for everything the SDK reads from the JWT. Only InsumerAPI's attestation signing keys are accepted: the ES256 JWT must be signed by `insumer-attest-v1` or `insumer-attest-v2`, and its companion by `insumer-attest-pq1`. A malformed `pqRequiredFrom` stops the middleware at startup. The optional peer loads under bundlers (webpack/Next.js, Turbopack, Vite) as well as plain Node.

## Pricing

The SDK is free and MIT-licensed. Each wallet-signed request hits InsumerAPI's `/v1/attest` once per `cacheTtlMs` window per (wallet, collection); cached results inside that window skip the upstream call. With the default `cacheTtlMs: 2000`, a wallet sending five requests in a second triggers one attest call. Adopters running high-throughput or revocation-sensitive flows can shrink the cache or set `cacheTtlMs: 0` to disable it. API-key requests never touch InsumerAPI.

When `/v1/attest` is unreachable, the SDK falls back to its most recent cached result if available and no more than 60 seconds past expiry (`MAX_STALE_FALLBACK_MS`). Beyond that window it fails closed with a 503. Adopters who need stricter revocation propagation can set `cacheTtlMs: 0` to opt out of cache + grace entirely.

## Distributed by

[Skye Meta Corp.](https://skyemeta.com): wrapper layer over [InsumerAPI](https://insumermodel.com) (the wallet-auth primitive: condition-based access, ECDSA-signed booleans with an ML-DSA-65 post-quantum companion, JWKS-verifiable, 37 chains).

## License

MIT
