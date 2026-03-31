import jwt from 'jsonwebtoken';
import { logger } from '@librechat/data-schemas';
import type { JwtHeader } from 'jsonwebtoken';
import type { SigningKey } from 'jwks-rsa';
import type { JwksSigner, RawClaims } from './types';
import { base64UrlDecode } from './utils';

/**
 * Verify a JWT against a single signer.
 * Returns the decoded payload on success, null on failure.
 */
export function trySignerVerify(
  token: string,
  signer: JwksSigner,
): Promise<RawClaims | null> {
  const verifyOptions: jwt.VerifyOptions = {
    algorithms: signer.algorithms,
  };

  if (signer.issuer) {
    verifyOptions.issuer = signer.issuer;
  }
  if (signer.audience) {
    verifyOptions.audience = signer.audience;
  }

  const getKey = (
    header: JwtHeader,
    callback: (err: Error | null, key?: string) => void,
  ): void => {
    if (signer.publicKey) {
      callback(null, signer.publicKey);
      return;
    }
    if (!signer.client) {
      callback(new Error(`Signer ${signer.index}: no JWKS client or public key`));
      return;
    }
    signer.client.getSigningKey(header.kid, (err: Error | null, key?: SigningKey) => {
      if (err) {
        callback(err);
        return;
      }
      callback(null, key?.getPublicKey());
    });
  };

  return new Promise((resolve) => {
    jwt.verify(
      token,
      getKey as jwt.GetPublicKeyOrSecret,
      verifyOptions,
      (err, decoded) => {
        if (err) {
          logger.debug(
            `[trustedHeaderAuth] Signer ${signer.index} verification failed: ${err.message}`,
          );
          resolve(null);
        } else {
          resolve(decoded as RawClaims);
        }
      },
    );
  });
}

/**
 * Unwrap a potentially base64-encoded JWT value.
 * If the string already starts with 'eyJ' (base64url of '{"'), it is
 * assumed to be a raw JWT and returned as-is. Otherwise, attempt
 * base64 decoding.
 */
export function unwrapJwtValue(raw: string): string | null {
  if (raw.startsWith('eyJ')) {
    return raw;
  }
  try {
    return base64UrlDecode(raw).toString('utf-8');
  } catch (err) {
    logger.warn(
      `[trustedHeaderAuth] Failed to base64-decode JWT header: ${(err as Error).message}`,
    );
    return null;
  }
}

/**
 * Validate a JWT from the configured header.
 *
 * Routes to the correct signer using the JWT iss claim:
 * - If iss matches one or more configured signer issuers, try each in order
 *   (supports key rotation with multiple signers sharing an issuer).
 * - In single-signer mode with no issuer constraint, try the sole signer.
 * - Otherwise reject (fail-closed).
 *
 * Returns the decoded claims and the matched signer, or null on failure.
 */
export async function validateJwtHeader(
  headerValue: string,
  signers: JwksSigner[],
): Promise<{ claims: RawClaims; signer: JwksSigner } | null> {
  const token = unwrapJwtValue(headerValue);
  if (!token) {
    return null;
  }

  // Verify the token is a plausible JWT (three dot-separated segments)
  if (token.split('.').length !== 3) {
    logger.warn('[trustedHeaderAuth] JWT header value is not a valid JWT format');
    return null;
  }

  if (signers.length === 0) {
    logger.warn('[trustedHeaderAuth] No JWKS signers configured');
    return null;
  }

  // Decode without verifying to read iss for routing
  const unverified = jwt.decode(token, { complete: true });
  const iss = (unverified?.payload as Record<string, unknown>)?.iss as string | undefined;

  // Collect all signers whose configured issuer matches the JWT iss
  const issuerMatches = iss
    ? signers.filter((s) => s.issuer && s.issuer === iss)
    : [];

  if (issuerMatches.length > 0) {
    for (const signer of issuerMatches) {
      const claims = await trySignerVerify(token, signer);
      if (claims) {
        return { claims, signer };
      }
    }
    logger.warn(
      `[trustedHeaderAuth] JWT iss '${iss}' matched ${issuerMatches.length} signer(s) `
      + 'but all failed verification (fail-closed on iss match)',
    );
    return null;
  }

  // No issuer match -- single signer with no issuer constraint is the
  // only case where we proceed without an iss match.
  const isSingleSignerNoIssuer = signers.length === 1 && !signers[0].issuer;
  if (isSingleSignerNoIssuer) {
    const claims = await trySignerVerify(token, signers[0]);
    if (claims) {
      return { claims, signer: signers[0] };
    }
    return null;
  }

  const issDesc = iss ? `'${iss}'` : '(none)';
  logger.warn(
    `[trustedHeaderAuth] JWT iss ${issDesc} does not match any configured signer. `
    + 'Rejecting token.',
  );
  return null;
}
