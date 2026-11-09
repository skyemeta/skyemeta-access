import { CHAIN_IDS, type CollectionConfig } from './types.js';

interface CacheEntry {
  pass: boolean;
  expiresAt: number;
}

/**
 * Caches pass/fail verdicts per (wallet, chain, contract address). Every input that decides the
 * verdict is part of the key, so two tiers that share a contract address on different chains
 * never share a cached result.
 */
export class AttestationCache {
  private readonly entries = new Map<string, CacheEntry>();
  constructor(private readonly ttlMs: number) {}

  get(wallet: string, collection: CollectionConfig): boolean | undefined {
    if (this.ttlMs === 0) return undefined;
    const entry = this.entries.get(key(wallet, collection));
    if (!entry) return undefined;
    // An expired entry is kept (not deleted) so that getStale() can still serve it inside the
    // stale-fallback window when /v1/attest is unreachable; getStale() evicts beyond that window.
    if (entry.expiresAt <= Date.now()) return undefined;
    return entry.pass;
  }

  getStale(wallet: string, collection: CollectionConfig, maxStaleMs: number): boolean | undefined {
    const k = key(wallet, collection);
    const entry = this.entries.get(k);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt + maxStaleMs) {
      this.entries.delete(k);
      return undefined;
    }
    return entry.pass;
  }

  set(wallet: string, collection: CollectionConfig, pass: boolean): void {
    if (this.ttlMs === 0) return;
    this.entries.set(key(wallet, collection), {
      pass,
      expiresAt: Date.now() + this.ttlMs,
    });
  }
}

function key(wallet: string, collection: CollectionConfig): string {
  // The chain is keyed by the chainId sent to /v1/attest; an unknown name is kept as its own value.
  const chain = CHAIN_IDS[collection.chain] ?? `name:${String(collection.chain)}`;
  return JSON.stringify([wallet.toLowerCase(), chain, collection.address.toLowerCase()]);
}
