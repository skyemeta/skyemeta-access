# Changelog

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
