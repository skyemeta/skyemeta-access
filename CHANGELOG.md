# Changelog

## 0.3.0 (2026-11-09)

Security: the sign-in message parser is strict and runs in linear time.

Before 0.3.0 the `Authorization: Wallet` message was matched with a pattern that backtracked
quadratically on a long run of spaces in its first line, before any signature or nonce check.
A 12 KB header cost about 60 ms of blocked event loop per request on Node 22; it now costs
well under a millisecond. The parser also followed EIP-4361 loosely.

- The header is refused above 8 KB and the message above 4 KB, before anything is parsed
  (`MAX_AUTHORIZATION_HEADER_LENGTH`, `MAX_SIWE_MESSAGE_LENGTH`).
- The message is read line by line in EIP-4361 order. Refused now: a domain with whitespace, an
  address that is not EIP-55 checksummed, a Version other than `1`, fields out of order or
  repeated, unknown lines, a nonce shorter than 8 letters or digits, and timestamps that do not
  parse.
- Expiration Time and Not Before are enforced when the signer includes them, on top of the
  existing five-minute window after Issued At.
- `ParsedSiwe` carries `expirationTime`, `notBefore` and `requestId` when present.
- Regression tests in `test/siwe.test.mjs`.

Upgrade: `npm install @skyemeta/access@0.3.0`. No configuration changes. Clients that build the
message with viem's `createSiweMessage`, or with `account.address` as in the example agent,
already produce what 0.3.0 accepts. A client that lowercases the address must send the
checksummed form.

## 0.2.7 (2026-11-09)

Security: the attestation cache is now keyed on the wallet, the chain and the contract address.

Before 0.2.7 the cache key held only the wallet and the contract address. In one `Access`
instance, two tiers that use the same contract address on different chains (common with
deterministic deployments) shared one cached verdict, so a holder on one chain could pass
the other chain's tier from cache. The window was the cache TTL (2 seconds by default), plus
up to 60 seconds through the stale fallback while /v1/attest was unreachable.

Found in an internal review. It is the same kind of flaw as the advisory for the sibling package
`@insumermodel/mppx-condition-gate` (GHSA-jxpm-8jpg-38xc, fixed in 3.2.2), where a cache key
left out `matchMode`.

Also in this release:

- `localMode.mockAttest` now receives the collection's chain as a third argument. Existing
  two-argument mocks keep working.
- Regression tests (`npm test`): same address on two chains, repeat hits, and the stale fallback.

Upgrade: `npm install @skyemeta/access@0.2.7`. No configuration changes.
