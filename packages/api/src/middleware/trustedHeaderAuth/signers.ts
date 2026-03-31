import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { logger } from '@librechat/data-schemas';
import type {
  SignerClaimPaths,
  JwksSignerConfig,
  JwksSigner,
} from './types';
import { isEnabled } from '~/utils';
import { env } from './env';

const PREFIX = 'TRUSTED_HEADER_AUTH';

const VALID_ALGORITHMS = new Set([
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512',
  'EdDSA',
]);

/** Default claim mapping paths matching standard OIDC claims. */
export const DEFAULT_CLAIM_PATHS: SignerClaimPaths = {
  sub: 'sub',
  email: 'email',
  username: 'preferred_username',
  name: 'name',
  picture: 'picture',
  emailVerified: 'email_verified',
};

/**
 * Read an indexed signer env var: TRUSTED_HEADER_AUTH_JWKS_<index>_<suffix>.
 * For indexes 0-9, also checks the zero-padded form (00-09) as fallback.
 */
function signerEnv(index: number, suffix: string): string | undefined {
  const unpadded = process.env[`${PREFIX}_JWKS_${index}_${suffix}`];
  if (unpadded !== undefined) {
    return unpadded;
  }
  if (index < 10) {
    const padded = String(index).padStart(2, '0');
    return process.env[`${PREFIX}_JWKS_${padded}_${suffix}`] ?? undefined;
  }
  return undefined;
}

/**
 * Resolve claim paths for a signer slot.
 *
 * In single-signer mode: per-signer > global USERINFO_*_CLAIM > default.
 * In multi-signer mode without GLOBAL_CLAIMS_FALLBACK: per-signer > default.
 * In multi-signer mode with GLOBAL_CLAIMS_FALLBACK: per-signer > global > default.
 */
export function resolveClaimPaths(index: number, allowGlobalFallback: boolean): SignerClaimPaths {
  const resolve = (
    signerSuffix: string,
    globalSuffix: string,
    defaultValue: string,
  ): string => {
    const perSigner = signerEnv(index, signerSuffix);
    if (perSigner) {
      return perSigner;
    }
    if (allowGlobalFallback) {
      const global = env(globalSuffix);
      if (global) {
        return global;
      }
    }
    return defaultValue;
  };

  return {
    sub: resolve('SUB_CLAIM', 'USERINFO_SUB_CLAIM', DEFAULT_CLAIM_PATHS.sub),
    email: resolve('EMAIL_CLAIM', 'USERINFO_EMAIL_CLAIM', DEFAULT_CLAIM_PATHS.email),
    username: resolve('USERNAME_CLAIM', 'USERINFO_USERNAME_CLAIM', DEFAULT_CLAIM_PATHS.username),
    name: resolve('NAME_CLAIM', 'USERINFO_NAME_CLAIM', DEFAULT_CLAIM_PATHS.name),
    picture: resolve('PICTURE_CLAIM', 'USERINFO_PICTURE_CLAIM', DEFAULT_CLAIM_PATHS.picture),
    emailVerified: resolve(
      'EMAIL_VERIFIED_CLAIM',
      'USERINFO_EMAIL_VERIFIED_CLAIM',
      DEFAULT_CLAIM_PATHS.emailVerified,
    ),
  };
}

/**
 * Parse a single indexed signer from env vars.
 * Returns null if neither URI nor PUBLIC_KEY is set for the index.
 */
export function parseSignerConfig(index: number, allowGlobalFallback: boolean): JwksSignerConfig | null {
  const uri = signerEnv(index, 'URI');
  const publicKey = signerEnv(index, 'PUBLIC_KEY');

  if (!uri && !publicKey) {
    return null;
  }

  const algorithmsRaw = signerEnv(index, 'ALGORITHMS') ?? 'RS256';
  const parsed = algorithmsRaw.split(',').map((a) => a.trim()).filter(Boolean);
  const invalid = parsed.filter((a) => !VALID_ALGORITHMS.has(a));
  if (invalid.length > 0) {
    logger.warn(`[trustedHeaderAuth] Unrecognized JWT algorithm(s): ${invalid.join(', ')}`);
  }
  const algorithms = parsed.filter((a) => VALID_ALGORITHMS.has(a)) as jwt.Algorithm[];
  if (algorithms.length === 0) {
    logger.warn(`[trustedHeaderAuth] Signer ${index} has no valid algorithms configured`);
  }

  const assumeRaw = signerEnv(index, 'ASSUME_EMAIL_VERIFIED')
    ?? (allowGlobalFallback ? env('ASSUME_EMAIL_VERIFIED', 'false') : 'false');

  return {
    uri: uri ?? undefined,
    publicKey: publicKey ?? undefined,
    issuer: signerEnv(index, 'ISSUER'),
    audience: signerEnv(index, 'AUDIENCE'),
    algorithms,
    claims: resolveClaimPaths(index, allowGlobalFallback),
    assumeVerified: isEnabled(assumeRaw),
  };
}

/**
 * Build a signer from the legacy non-indexed env vars (JWT_JWKS_URI, etc.).
 * Returns null if no legacy JWT config exists.
 */
export function parseLegacySigner(): JwksSignerConfig | null {
  const uri = env('JWT_JWKS_URI');
  const publicKey = env('JWT_PUBLIC_KEY');

  if (!uri && !publicKey) {
    return null;
  }

  const algorithmsRaw = env('JWT_ALGORITHMS', 'RS256');
  const parsedLegacy = algorithmsRaw.split(',').map((a) => a.trim()).filter(Boolean);
  const invalidLegacy = parsedLegacy.filter((a) => !VALID_ALGORITHMS.has(a));
  if (invalidLegacy.length > 0) {
    logger.warn(`[trustedHeaderAuth] Unrecognized JWT algorithm(s): ${invalidLegacy.join(', ')}`);
  }
  const algorithms = parsedLegacy.filter((a) => VALID_ALGORITHMS.has(a)) as jwt.Algorithm[];
  if (algorithms.length === 0) {
    logger.warn('[trustedHeaderAuth] Legacy signer has no valid algorithms configured');
  }

  return {
    uri: uri ?? undefined,
    publicKey: publicKey ?? undefined,
    issuer: env('JWT_ISSUER'),
    audience: env('JWT_AUDIENCE'),
    algorithms,
    claims: {
      sub: env('USERINFO_SUB_CLAIM', DEFAULT_CLAIM_PATHS.sub),
      email: env('USERINFO_EMAIL_CLAIM', DEFAULT_CLAIM_PATHS.email),
      username: env('USERINFO_USERNAME_CLAIM', DEFAULT_CLAIM_PATHS.username),
      name: env('USERINFO_NAME_CLAIM', DEFAULT_CLAIM_PATHS.name),
      picture: env('USERINFO_PICTURE_CLAIM', DEFAULT_CLAIM_PATHS.picture),
      emailVerified: env('USERINFO_EMAIL_VERIFIED_CLAIM', DEFAULT_CLAIM_PATHS.emailVerified),
    },
    assumeVerified: isEnabled(env('ASSUME_EMAIL_VERIFIED', 'false')),
  };
}

/**
 * Create a jwks-rsa client for a signer with a JWKS URI.
 */
export function createJwksClient(uri: string): jwksRsa.JwksClient {
  return jwksRsa({
    jwksUri: uri,
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 600000,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
  });
}

interface IndexedSlot {
  index: number;
  hasUri: boolean;
  hasPublicKey: boolean;
}

/**
 * Detect which indexed slots have URI or PUBLIC_KEY configured.
 * For indexes 0-9, also checks zero-padded variants (00-09) to
 * support operators who pad env var names for sorting.
 * Unpadded form takes precedence via signerEnv().
 */
function scanIndexedSigners(): IndexedSlot[] {
  const slots: IndexedSlot[] = [];
  for (let i = 0; i < 100; i++) {
    const hasUri = !!signerEnv(i, 'URI');
    const hasPublicKey = !!signerEnv(i, 'PUBLIC_KEY');
    if (hasUri || hasPublicKey) {
      slots.push({ index: i, hasUri, hasPublicKey });
    }
  }
  return slots;
}

/** Resolve claim paths for each indexed signer, respecting global fallback. */
function resolveSignerClaims(
  configs: JwksSignerConfig[],
  slots: IndexedSlot[],
  globalClaimsFallback: boolean,
): void {
  const isMultiSigner = configs.length > 1;

  if (!isMultiSigner || globalClaimsFallback) {
    return;
  }

  for (let i = 0; i < configs.length; i++) {
    configs[i].claims = resolveClaimPaths(slots[i].index, false);
  }
}

/** Construct runtime signer objects with JWKS clients. */
function buildRuntimeSigners(configs: JwksSignerConfig[]): JwksSigner[] {
  return configs.map((config, i) => ({
    ...config,
    client: config.uri ? createJwksClient(config.uri) : null,
    index: i,
  }));
}

/** Warn when no explicit per-signer claim mappings are set. */
function warnMissingClaimMappings(
  slots: IndexedSlot[],
  globalClaimsFallback: boolean,
): void {
  for (const slot of slots) {
    const hasAnyClaim = signerEnv(slot.index, 'SUB_CLAIM')
      || signerEnv(slot.index, 'EMAIL_CLAIM')
      || signerEnv(slot.index, 'USERNAME_CLAIM')
      || signerEnv(slot.index, 'NAME_CLAIM')
      || signerEnv(slot.index, 'PICTURE_CLAIM')
      || signerEnv(slot.index, 'EMAIL_VERIFIED_CLAIM');

    if (!hasAnyClaim && !globalClaimsFallback) {
      logger.warn(
        `[trustedHeaderAuth] Signer ${slot.index} has no per-signer claim mappings and `
        + 'JWKS_GLOBAL_CLAIMS_FALLBACK is disabled. Using OIDC standard defaults '
        + '(sub, email, preferred_username, name, picture, email_verified). Set per-signer '
        + 'JWKS_N_*_CLAIM vars or enable JWKS_GLOBAL_CLAIMS_FALLBACK=true.',
      );
    }
  }
}

/**
 * Warn if both legacy JWT_* env vars and indexed JWKS_N_* vars coexist.
 * Legacy vars are silently ignored in indexed mode, which may confuse operators.
 */
function warnLegacyIndexedCoexistence(): void {
  const hasLegacy = !!env('JWT_JWKS_URI') || !!env('JWT_PUBLIC_KEY');
  if (!hasLegacy) {
    return;
  }
  logger.warn(
    '[trustedHeaderAuth] Legacy JWT_* env vars detected alongside indexed JWKS_N_* vars. '
    + 'Legacy vars are ignored in indexed mode. Convert to JWKS_0_* format.',
  );
}

/** Encapsulates signer registry state in a closure instead of a bare module-level let. */
function createSignerCache() {
  let cached: JwksSigner[] | null = null;
  return {
    get(): JwksSigner[] {
      if (cached) {
        return cached;
      }

      const slots = scanIndexedSigners();
      const hasIndexed = slots.length > 0;

      if (hasIndexed) {
        warnLegacyIndexedCoexistence();
      }

      const globalClaimsFallback = isEnabled(env('JWKS_GLOBAL_CLAIMS_FALLBACK', 'false'));

      const legacy = hasIndexed ? null : parseLegacySigner();
      const configs: JwksSignerConfig[] = hasIndexed
        ? slots.map((slot) => parseSignerConfig(slot.index, true) as JwksSignerConfig)
        : legacy ? [legacy] : [];

      if (hasIndexed && configs.length > 1) {
        resolveSignerClaims(configs, slots, globalClaimsFallback);
        warnMissingClaimMappings(slots, globalClaimsFallback);
      }

      cached = buildRuntimeSigners(configs);

      if (cached.length > 0) {
        const mode = cached.length > 1 ? 'multi-signer' : 'single-signer';
        logger.info(`[trustedHeaderAuth] Initialized ${cached.length} signer(s) (${mode} mode)`);
      }

      return cached;
    },
    reset(): void {
      cached = null;
    },
  };
}

const signerCache = createSignerCache();

/**
 * Initialize the signer registry from env vars.
 *
 * Scans JWKS_0..JWKS_99 indexed env vars (and zero-padded 00-09 variants).
 * If none found, falls back to legacy single-signer vars. Validates claim
 * completeness in multi-signer mode.
 *
 * Exported for testing.
 */
export function initSigners(): JwksSigner[] {
  return signerCache.get();
}

/** Reset the signer registry. Exported for testing only. */
export function resetSigners(): void {
  signerCache.reset();
}
