import jwt from 'jsonwebtoken';
import { createHash } from 'crypto';
import type { Request } from 'express';
import type {
  HeaderAuthClaims,
  JwksSigner,
  CachedClaimsConfig,
} from './types';
import { unwrapJwtValue } from './jwt';
import { extractClaims } from './claims';
import { env } from './env';

const JWKS_CACHE_TTL_MS = 60_000;
const JWKS_CACHE_DEFAULT_MAX_ENTRIES = 1_000;
const JWKS_CACHE_PRUNE_INTERVAL = 100;

interface CachedClaims {
  claims: HeaderAuthClaims;
  expiry: number;
}

/** Compute a fixed-length SHA-256 cache key from the raw JWT string. */
function computeCacheKey(rawHeaderValue: string): string {
  return createHash('sha256').update(rawHeaderValue).digest('base64url');
}

/** Remove expired entries, then FIFO-evict oldest insertions (Map iterates in insertion order). */
function pruneExpiredEntries(
  cacheMap: Map<string, CachedClaims>,
  maxEntries: number,
): void {
  const now = Date.now();
  for (const [key, entry] of cacheMap) {
    if (now >= entry.expiry) {
      cacheMap.delete(key);
    }
  }

  if (cacheMap.size <= maxEntries) {
    return;
  }

  let toEvict = cacheMap.size - maxEntries;
  for (const key of cacheMap.keys()) {
    if (toEvict <= 0) {
      break;
    }
    cacheMap.delete(key);
    toEvict--;
  }
}

/**
 * Encapsulates JWKS claims cache state in a closure.
 *
 * Intentionally in-memory (not Redis) because:
 * - Amortizes CPU-bound JWT signature verification (~1-5ms). A Redis
 *   round-trip (~0.5-2ms) would consume most of the savings.
 * - No cross-replica dependency -- each request carries its own JWT
 *   header, so no replica needs another's cached validation result.
 * - 60s TTL keeps worst-case redundant work to one verify per token
 *   per container per minute.
 * - Process-isolated storage avoids expanding the security surface
 *   (a compromised Redis could otherwise inject forged identity claims).
 */
function createJwksCache() {
  const cacheMap = new Map<string, CachedClaims>();
  let callCount = 0;

  return {
    get(key: string): CachedClaims | undefined {
      return cacheMap.get(key);
    },
    set(key: string, entry: CachedClaims, maxEntries: number): void {
      cacheMap.set(key, entry);
      callCount++;
      if (callCount % JWKS_CACHE_PRUNE_INTERVAL === 0 || cacheMap.size >= maxEntries) {
        pruneExpiredEntries(cacheMap, maxEntries);
      }
    },
    size(): number {
      return cacheMap.size;
    },
    reset(): void {
      cacheMap.clear();
      callCount = 0;
    },
  };
}

const jwksCache = createJwksCache();

/**
 * Compute cache expiry capped at the JWT's exp claim.
 * If the JWT has no exp or is not parseable, falls back to the standard TTL.
 */
function computeCacheExpiry(rawHeader: string): number {
  const defaultExpiry = Date.now() + JWKS_CACHE_TTL_MS;
  const token = unwrapJwtValue(rawHeader) ?? rawHeader;
  const decoded = jwt.decode(token, { complete: true });
  const exp = (decoded?.payload as jwt.JwtPayload)?.exp;
  if (typeof exp !== 'number') {
    return defaultExpiry;
  }
  const jwtExpiryMs = exp * 1000;
  return Math.min(defaultExpiry, jwtExpiryMs);
}

/**
 * Return cached claims for a JWT header value, or extract fresh claims.
 * Uses a module-level cache with 60s TTL to avoid redundant JWT
 * verification on every authenticated request.
 *
 * Only caches JWKS-signed JWT results -- unsigned/userinfo paths bypass
 * the cache entirely since they have no expensive crypto to amortize.
 */
export async function getCachedOrExtractClaims(
  req: Request,
  signers: JwksSigner[],
  config?: CachedClaimsConfig,
): Promise<HeaderAuthClaims | null> {
  const defaults = {
    trustUnsigned: false,
    assumeEmailVerified: false,
    jwtHeader: 'X-Id-Token',
    userinfoHeader: 'X-Userinfo',
    emailHeader: 'X-Forwarded-Email',
    jwksCacheMaxEntries: JWKS_CACHE_DEFAULT_MAX_ENTRIES,
  } as const;
  const resolved = {
    ...defaults,
    ...config,
    trustedCidrs: config?.trustedCidrs ?? env('TRUSTED_CIDRS', '0.0.0.0/0,::/0'),
  };
  const rawHeader = req.headers[resolved.jwtHeader.toLowerCase()] as string | undefined;

  const cacheKey = rawHeader ? computeCacheKey(rawHeader) : null;

  if (cacheKey) {
    const cached = jwksCache.get(cacheKey);
    if (cached && Date.now() < cached.expiry) {
      return cached.claims;
    }
  }

  const claims = await extractClaims(req, signers, resolved);

  if (claims && cacheKey) {
    const expiry = computeCacheExpiry(rawHeader as string);
    jwksCache.set(cacheKey, { claims, expiry }, resolved.jwksCacheMaxEntries);
  }

  return claims;
}

/** Reset the JWKS claims cache. Exported for testing only. */
export function resetJwksCache(): void {
  jwksCache.reset();
}

/** Expose cache size for testing. */
export function getJwksCacheSize(): number {
  return jwksCache.size();
}
