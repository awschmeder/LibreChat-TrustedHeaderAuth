import { logger } from '@librechat/data-schemas';
import type { Request } from 'express';
import type {
  HeaderAuthClaims,
  SignerClaimPaths,
  RawClaims,
  JwksSigner,
  ClaimsExtractionConfig,
} from './types';
import { validateJwtHeader } from './jwt';
import { base64UrlDecode, getByPath } from './utils';
import { DEFAULT_CLAIM_PATHS } from './signers';
import { isCidrStrict } from './network';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Coerce an unknown claim value to a string.
 *
 * Arrays use the first element (recursively); null/undefined return '' silently;
 * numbers, booleans, and arrays are coerced silently (common IdP variations);
 * objects return '' with a warning.
 */
export function coerceClaimToString(value: unknown, fieldName: string): string {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    return coerceClaimToString(value[0], fieldName);
  }
  logger.warn(
    `[trustedHeaderAuth] Claim "${fieldName}" is an unsupported type (object), returning empty string`,
  );
  return '';
}

/**
 * Decode the userinfo header (base64-encoded JSON).
 */
export function decodeUserinfoHeader(headerValue: string): RawClaims | null {
  try {
    const decoded = base64UrlDecode(headerValue).toString('utf-8');
    return JSON.parse(decoded) as RawClaims;
  } catch (err) {
    logger.warn(
      `[trustedHeaderAuth] Failed to decode userinfo header: ${(err as Error).message}`,
    );
    return null;
  }
}

/**
 * Extract email from the forwarded-email header.
 * Validates non-empty local part, single @, non-empty domain with TLD.
 */
export function extractEmailHeader(headerValue: string): string | null {
  const email = headerValue?.trim();
  if (!email) {
    logger.warn('[trustedHeaderAuth] Forwarded email header is empty');
    return null;
  }
  if (!EMAIL_REGEX.test(email)) {
    logger.warn('[trustedHeaderAuth] Forwarded email header is invalid', { email });
    return null;
  }
  return email;
}

/**
 * Map raw claims to a normalized user profile using the provided claim paths.
 *
 * Coerces string-valued email_verified ("true"/"false") to boolean for
 * compatibility with IdPs that return stringified booleans. When the
 * claim is absent or an unexpected type, falls back to assumeVerified
 * (default false -- fail-closed).
 */
export function mapClaims(
  claims: RawClaims,
  claimPaths: SignerClaimPaths = DEFAULT_CLAIM_PATHS,
  assumeVerified = false,
): HeaderAuthClaims {
  const rawVerified = getByPath(claims, claimPaths.emailVerified);
  let emailVerified: boolean;
  if (typeof rawVerified === 'string') {
    emailVerified = rawVerified.toLowerCase() === 'true';
  } else if (typeof rawVerified === 'boolean') {
    emailVerified = rawVerified;
  } else {
    if (rawVerified !== undefined && rawVerified !== null) {
      logger.debug(
        `[trustedHeaderAuth] Unexpected email_verified type: ${typeof rawVerified}`,
      );
    }
    emailVerified = assumeVerified;
  }

  return {
    sub: coerceClaimToString(getByPath(claims, claimPaths.sub), 'sub') || '',
    email: coerceClaimToString(getByPath(claims, claimPaths.email), 'email') || '',
    username: coerceClaimToString(getByPath(claims, claimPaths.username), 'username') || '',
    name: coerceClaimToString(getByPath(claims, claimPaths.name), 'name') || '',
    picture: coerceClaimToString(getByPath(claims, claimPaths.picture), 'picture') || '',
    emailVerified,
  };
}

/**
 * Extract and validate identity claims from request headers.
 * Priority: Signed JWT header > Unsigned Userinfo header > Unsigned Email header.
 * Unsigned sources require TRUST_UNSIGNED=true.
 */
export async function extractClaims(
  req: Request,
  signers: JwksSigner[],
  config: ClaimsExtractionConfig,
): Promise<HeaderAuthClaims | null> {
  const { trustUnsigned, assumeEmailVerified: globalAssumeVerified } = config;

  // 1. Try signed JWT header (always attempted when signers are configured)
  const jwtHeaderName = config.jwtHeader;
  const jwtHeaderValue = req.headers[jwtHeaderName.toLowerCase()] as string | undefined;

  const hasJwtConfig = signers.length > 0;

  if (jwtHeaderValue && hasJwtConfig) {
    const result = await validateJwtHeader(jwtHeaderValue, signers);
    if (result) {
      logger.debug('[trustedHeaderAuth] Claims extracted from validated JWT');
      return mapClaims(result.claims, result.signer.claims, result.signer.assumeVerified);
    }
    // JWT present but validation failed -- do not fall through to unsigned
    // sources. Prevents downgrade attacks where a forged JWT causes
    // fallback to an unsigned header.
    logger.warn(
      '[trustedHeaderAuth] JWT header present but validation failed; '
      + 'not falling through to unsigned sources',
    );
    return null;
  }

  // 2. Try unsigned headers if allowed
  if (trustUnsigned) {
    // Refuse unsigned headers unless the operator has locked down the source CIDR.
    if (!isCidrStrict(config.trustedCidrs)) {
      logger.error(
        '[trustedHeaderAuth] TRUST_UNSIGNED=true requires a strict TRUSTED_CIDRS value '
        + '(not 0.0.0.0/0, ::/0 or unset). Unsigned headers rejected. '
        + 'Set TRUSTED_HEADER_AUTH_TRUSTED_CIDRS to the proxy IP/subnet.',
      );
      return null;
    }

    // Try Userinfo header if present
    const userinfoHeaderName = config.userinfoHeader;
    const userinfoValue = req.headers[userinfoHeaderName.toLowerCase()] as string | undefined;
    if (userinfoValue) {
      const userinfoClaims = decodeUserinfoHeader(userinfoValue);
      if (userinfoClaims) {
        logger.debug('[trustedHeaderAuth] Claims extracted from unsigned userinfo header');
        return mapClaims(userinfoClaims, DEFAULT_CLAIM_PATHS, globalAssumeVerified);
      }
    }

    // Try forwarded email header if present
    const emailHeaderName = config.emailHeader;
    const emailValue = req.headers[emailHeaderName.toLowerCase()] as string | undefined;
    if (emailValue) {
      const email = extractEmailHeader(emailValue);
      if (email) {
        logger.debug('[trustedHeaderAuth] Claims extracted from forwarded email header');
        const username = email.split('@')[0];
        return {
          sub: email,
          email,
          username,
          name: username,
          picture: '',
          emailVerified: globalAssumeVerified,
        };
      }
    }
  }

  return null;
}
