import { logger } from '@librechat/data-schemas';
import type { FrozenConfig } from './types';
import { isEnabled } from '~/utils';

const PREFIX = 'TRUSTED_HEADER_AUTH';

/**
 * Read an env var with the TRUSTED_HEADER_AUTH_ prefix.
 * Intended for use during initialization only -- not per-request.
 */
export function env(suffix: string, fallback: string): string;
export function env(suffix: string): string | undefined;
export function env(suffix: string, fallback?: string): string | undefined {
  return process.env[`${PREFIX}_${suffix}`] ?? fallback;
}

/**
 * Snapshot every per-request env setting into an immutable config object.
 *
 * ENABLED is intentionally excluded from FrozenConfig because logConfig
 * reads it at startup even when the feature is disabled, before
 * FrozenConfig is constructed.
 */
export function readAllConfig(isEnabledFn: (v: string | undefined) => boolean = isEnabled): Readonly<FrozenConfig> {
  const allowDomainsRaw = env('ALLOW_DOMAINS', '*');
  const parsedAllowDomains = allowDomainsRaw.trim() === '*'
    ? new Set<string>()
    : new Set(
      allowDomainsRaw.split(',').map((d) => d.trim().toLowerCase()).filter(Boolean),
    );

  const maxHopsRaw = env('MAX_HOPS', '1');
  let maxHops = parseInt(maxHopsRaw, 10);
  if (isNaN(maxHops)) {
    logger.warn(
      `[trustedHeaderAuth] TRUSTED_HEADER_AUTH_MAX_HOPS="${maxHopsRaw}" is not a valid integer; `
      + 'defaulting to 1',
    );
    maxHops = 1;
  } else if (maxHops < 0) {
    logger.warn(
      `[trustedHeaderAuth] TRUSTED_HEADER_AUTH_MAX_HOPS=${maxHops} is negative; defaulting to 1`,
    );
    maxHops = 1;
  }

  const jwksCacheMaxEntriesRaw = env('JWKS_CACHE_MAX_ENTRIES', '1000');
  let jwksCacheMaxEntries = parseInt(jwksCacheMaxEntriesRaw, 10);
  if (isNaN(jwksCacheMaxEntries)) {
    logger.warn(
      `[trustedHeaderAuth] TRUSTED_HEADER_AUTH_JWKS_CACHE_MAX_ENTRIES="${jwksCacheMaxEntriesRaw}" is not a valid integer; `
      + 'defaulting to 1000',
    );
    jwksCacheMaxEntries = 1000;
  } else if (jwksCacheMaxEntries < 0) {
    logger.warn(
      `[trustedHeaderAuth] TRUSTED_HEADER_AUTH_JWKS_CACHE_MAX_ENTRIES=${jwksCacheMaxEntries} is negative; defaulting to 1000`,
    );
    jwksCacheMaxEntries = 1000;
  }

  return Object.freeze({
    trustedCidrs: env('TRUSTED_CIDRS', '0.0.0.0/0,::/0'),
    maxHops,
    trustUnsigned: isEnabledFn(env('TRUST_UNSIGNED', 'false')),
    assumeEmailVerified: isEnabledFn(env('ASSUME_EMAIL_VERIFIED', 'false')),
    jwtHeader: env('JWT_HEADER', 'X-Id-Token'),
    userinfoHeader: env('USERINFO_HEADER', 'X-Userinfo'),
    emailHeader: env('EMAIL_HEADER', 'X-Forwarded-Email'),
    allowDomains: allowDomainsRaw,
    parsedAllowDomains,
    jwksCacheMaxEntries,
  });
}

/** Cached config singleton for use by the standalone extractClaims wrapper. */
let cachedConfig: Readonly<FrozenConfig> | null = null;

/** Return a cached FrozenConfig, creating it on first call. */
export function getCachedConfig(): Readonly<FrozenConfig> {
  if (cachedConfig) {
    return cachedConfig;
  }
  cachedConfig = readAllConfig();
  return cachedConfig;
}

/** Reset the cached config. Exported for testing only. */
export function resetCachedConfig(): void {
  cachedConfig = null;
}
