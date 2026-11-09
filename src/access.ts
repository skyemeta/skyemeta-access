import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AttestClient, DEFAULT_ATTEST_BASE_URL, DEFAULT_JWKS_URL } from './attest.js';
import { AttestationCache } from './cache.js';
import {
  AccessError,
  DisabledModeError,
  InvalidPassError,
  MisconfiguredTierError,
  MissingAuthError,
  NonceTtlTooShortError,
  ProductionMockError,
} from './errors.js';
import { InMemoryNonceStore } from './nonce-store.js';
import { extractEnvelope, verifySiwe } from './siwe.js';
import type { AccessConfig, CollectionConfig, NonceStore } from './types.js';
import type { PqResult } from './pq.js';

const DEFAULT_CACHE_TTL_MS = 2000;
const MIN_CACHE_TTL_MS = 100;
const MIN_NONCE_TTL_MS = 6 * 60 * 1000;
const DEFAULT_RETRY_COUNT = 1;
const MAX_STALE_FALLBACK_MS = 60_000;

export interface AccessRequest extends Request {
  skyemetaAccess?: {
    wallet: string;
    collection: CollectionConfig;
    tierKey: string;
    /**
     * Post-quantum companion verdict for the upstream attestation that admitted THIS request:
     * `verified`, `refuted`, `absent`, or `unverifiable` with a reason. Undefined when the
     * request was served from cache or in local mode.
     */
    pq?: PqResult;
  };
}

export class Access {
  private readonly insumerApiKey: string;
  private readonly collections: Record<string, CollectionConfig>;
  private readonly nonceStore: NonceStore;
  private readonly cacheTtlMs: number;
  private readonly cache: AttestationCache;
  private readonly disabled: boolean;
  private readonly siweDomain: string;
  private readonly localMode: AccessConfig['localMode'];
  private readonly attestClient: AttestClient;

  constructor(config: AccessConfig) {
    if (!config.insumerApiKey) {
      throw new Error('@skyemeta/access: insumerApiKey is required');
    }
    if (!config.collections || Object.keys(config.collections).length === 0) {
      throw new Error('@skyemeta/access: collections map must contain at least one entry');
    }
    if (!config.siweDomain) {
      throw new Error(
        '@skyemeta/access: siweDomain is required. Set it to the host your API serves SIWE messages for (e.g., "api.yourservice.com"). ' +
        'Behind a reverse proxy, do not rely on request-host inference — proxies can be tricked into forwarding spoofed Host headers.',
      );
    }

    if (config.localMode?.mockAttest && process.env.NODE_ENV !== 'development') {
      throw new ProductionMockError(process.env.NODE_ENV);
    }

    if (config.pqRequiredFrom !== undefined && isNaN(new Date(config.pqRequiredFrom).getTime())) {
      // A malformed cutoff is a configuration error: refuse to start rather than fail mid-request.
      throw new Error(`@skyemeta/access: pqRequiredFrom is not a valid date: ${String(config.pqRequiredFrom)}`);
    }

    if (config.nonceStore?.ttlMs !== undefined && config.nonceStore.ttlMs < MIN_NONCE_TTL_MS) {
      throw new NonceTtlTooShortError(config.nonceStore.ttlMs);
    }

    this.insumerApiKey = config.insumerApiKey;
    this.collections = config.collections;
    this.nonceStore = config.nonceStore ?? new InMemoryNonceStore();
    this.cacheTtlMs = resolveCacheTtl(config.cacheTtlMs);
    this.cache = new AttestationCache(this.cacheTtlMs);
    this.disabled = config.disabled === true;
    this.siweDomain = config.siweDomain;
    this.localMode = config.localMode;
    this.attestClient = new AttestClient(
      config.insumerApiKey,
      config.attestRetryCount ?? DEFAULT_RETRY_COUNT,
      config.attestBaseUrl ?? DEFAULT_ATTEST_BASE_URL,
      config.jwksUrl ?? DEFAULT_JWKS_URL,
      config.pqRequiredFrom,
    );

    this.emitStartupWarnings(config);
  }

  requireValidPassOrApiKey(apiKeyHandler: RequestHandler): RequestHandler;
  requireValidPassOrApiKey(tierKey: string, apiKeyHandler: RequestHandler): RequestHandler;
  requireValidPassOrApiKey(
    tierKeyOrHandler: string | RequestHandler,
    maybeHandler?: RequestHandler,
  ): RequestHandler {
    const { tierKey, apiKeyHandler } = this.normalizeMiddlewareArgs(tierKeyOrHandler, maybeHandler);
    this.assertTierKey(tierKey);
    const collection = this.collections[tierKey];

    return (req: Request, res: Response, next: NextFunction): void => {
      const hasApiKey = typeof req.headers['x-api-key'] === 'string';
      const hasWallet = typeof req.headers.authorization === 'string';

      if (this.disabled) {
        if (hasApiKey) return void apiKeyHandler(req, res, next);
        return this.sendError(res, new DisabledModeError());
      }

      if (hasApiKey && hasWallet) {
        console.warn(
          '@skyemeta/access: request contained both X-API-Key and Authorization: Wallet headers; routing to X-API-Key handler (precedence rule).',
        );
      }

      if (hasApiKey) return void apiKeyHandler(req, res, next);
      if (!hasWallet) return this.sendError(res, new MissingAuthError());

      this.handleWalletAuth(req as AccessRequest, res, next, tierKey, collection);
    };
  }

  requireValidPass(tierKey?: string): RequestHandler {
    const resolvedKey = tierKey ?? this.defaultTierKey();
    this.assertTierKey(resolvedKey);
    const collection = this.collections[resolvedKey];

    return (req: Request, res: Response, next: NextFunction): void => {
      if (this.disabled) return this.sendError(res, new DisabledModeError());
      const hasWallet = typeof req.headers.authorization === 'string';
      if (!hasWallet) {
        res.status(401).json({
          ok: false,
          error: {
            code: 401,
            message: 'This endpoint requires wallet authentication; use the wallet-auth path.',
          },
        });
        return;
      }
      this.handleWalletAuth(req as AccessRequest, res, next, resolvedKey, collection);
    };
  }

  /**
   * Post-quantum companion verdict from the most recent upstream `/v1/attest` call made by this
   * instance, whichever request triggered it. Instance-wide and therefore racy under load; for
   * the verdict that belongs to a specific request read `req.skyemetaAccess.pq` (undefined when
   * the request was served from cache or in local mode).
   */
  get lastPq(): PqResult | undefined {
    return this.attestClient.lastPq;
  }

  async hasValidPass(tierKey: string, walletAddress: string): Promise<boolean> {
    this.assertTierKey(tierKey);
    const collection = this.collections[tierKey];
    return (await this.checkPassWithCache(walletAddress, collection)).pass;
  }

  async verifyWalletSignIn(authorizationHeader: string | undefined): Promise<string> {
    const envelope = extractEnvelope(authorizationHeader);
    const { wallet } = await verifySiwe(envelope, {
      nonceStore: this.nonceStore,
      siweDomain: this.siweDomain,
    });
    return wallet;
  }

  private async handleWalletAuth(
    req: AccessRequest,
    res: Response,
    next: NextFunction,
    tierKey: string,
    collection: CollectionConfig,
  ): Promise<void> {
    try {
      const wallet = await this.verifyWalletSignIn(req.headers.authorization);
      const { pass, pq } = await this.checkPassWithCache(wallet, collection);
      if (!pass) return this.sendError(res, new InvalidPassError());
      // pq is the verdict from THIS request's upstream call; undefined on a cache hit or in local mode.
      req.skyemetaAccess = { wallet, collection, tierKey, pq };
      next();
    } catch (err) {
      if (err instanceof AccessError) return this.sendError(res, err);
      console.error('@skyemeta/access: unexpected error in wallet-auth path', err);
      res.status(500).json({ ok: false, error: { code: 500, message: 'Internal authentication error' } });
    }
  }

  private async checkPassWithCache(
    wallet: string,
    collection: CollectionConfig,
  ): Promise<{ pass: boolean; pq?: PqResult }> {
    const cached = this.cache.get(wallet, collection);
    if (cached !== undefined) return { pass: cached };

    try {
      let pass: boolean;
      let pq: PqResult | undefined;
      if (this.localMode?.mockAttest) {
        pass = Boolean(await this.localMode.mockAttest(wallet, collection.address, collection.chain));
      } else {
        const verdict = await this.attestClient.checkPassWithVerdict(wallet, collection);
        pass = verdict.pass;
        pq = verdict.pq;
      }
      this.cache.set(wallet, collection, pass);
      return { pass, pq };
    } catch (err) {
      const stale = this.cache.getStale(wallet, collection, MAX_STALE_FALLBACK_MS);
      if (stale !== undefined) {
        console.warn(
          `@skyemeta/access: /v1/attest unreachable; serving stale-cache result (within ${MAX_STALE_FALLBACK_MS}ms grace window)`,
        );
        return { pass: stale };
      }
      throw err;
    }
  }

  private sendError(res: Response, err: AccessError): void {
    res.status(err.suggestedStatus).json({
      ok: false,
      error: { code: err.suggestedStatus, message: err.message },
    });
  }

  private normalizeMiddlewareArgs(
    tierKeyOrHandler: string | RequestHandler,
    maybeHandler: RequestHandler | undefined,
  ): { tierKey: string; apiKeyHandler: RequestHandler } {
    if (typeof tierKeyOrHandler === 'string') {
      if (!maybeHandler) {
        throw new Error('@skyemeta/access: apiKeyHandler is required when tierKey is provided');
      }
      return { tierKey: tierKeyOrHandler, apiKeyHandler: maybeHandler };
    }
    return { tierKey: this.defaultTierKey(), apiKeyHandler: tierKeyOrHandler };
  }

  private defaultTierKey(): string {
    const keys = Object.keys(this.collections);
    if (keys.length === 1) return keys[0];
    if ('default' in this.collections) return 'default';
    throw new Error(
      `@skyemeta/access: tierKey is required when collections has multiple entries and no 'default'. Got keys: [${keys.join(', ')}].`,
    );
  }

  private assertTierKey(tierKey: string): void {
    if (!(tierKey in this.collections)) {
      throw new MisconfiguredTierError(tierKey, Object.keys(this.collections));
    }
  }

  private emitStartupWarnings(config: AccessConfig): void {
    if (this.disabled) {
      console.warn(
        '⚠ @skyemeta/access: DISABLED MODE ACTIVE. Wallet auth disabled; X-API-Key callers unaffected. This SDK is currently a pass-through.',
      );
    }

    if (!config.nonceStore) {
      console.warn(
        '⚠ @skyemeta/access: using in-memory nonceStore. SAFE for single-instance deployments only. ' +
        'If you\'re running on Cloud Functions, Lambda, or any autoscaling platform, configure a shared store (see docs).',
      );
    }

    if (config.cacheTtlMs !== undefined && config.cacheTtlMs > 0 && config.cacheTtlMs < MIN_CACHE_TTL_MS) {
      console.warn(
        `⚠ @skyemeta/access: cacheTtlMs=${config.cacheTtlMs}ms is below the ${MIN_CACHE_TTL_MS}ms minimum floor; using ${MIN_CACHE_TTL_MS}ms. ` +
        'Pass cacheTtlMs: 0 to truly disable caching (rate-limit risk).',
      );
    }

    if (this.localMode?.mockAttest) {
      console.warn(
        '⚠ @skyemeta/access: localMode.mockAttest is active. /v1/attest will NOT be called. Development only — production-guarded by NODE_ENV check.',
      );
    }
  }
}

function resolveCacheTtl(input: number | undefined): number {
  if (input === undefined) return DEFAULT_CACHE_TTL_MS;
  if (input === 0) return 0;
  return Math.max(input, MIN_CACHE_TTL_MS);
}

