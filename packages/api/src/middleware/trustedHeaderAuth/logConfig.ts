import { logger } from '@librechat/data-schemas';
import type { JwksSigner } from './types';
import { isCidrStrict } from './network';
import { isEnabled } from '~/utils';
import { env } from './env';

/**
 * Log configuration at startup for operator verification.
 */
export function logConfig(signers: JwksSigner[]): void {
  const enabled = isEnabled(env('ENABLED', 'false'));
  if (!enabled) {
    return;
  }

  const trustUnsigned = isEnabled(env('TRUST_UNSIGNED', 'false'));
  const cidrStrict = isCidrStrict();

  logger.info('[trustedHeaderAuth] === Configuration ===');
  logger.info(`[trustedHeaderAuth] JWT header: ${env('JWT_HEADER', 'X-Id-Token')}`);
  logger.info(`[trustedHeaderAuth] Userinfo header: ${env('USERINFO_HEADER', 'X-Userinfo')}`);
  logger.info(`[trustedHeaderAuth] Email header: ${env('EMAIL_HEADER', 'X-Forwarded-Email')}`);
  logger.info(`[trustedHeaderAuth] Trusted CIDRs: ${env('TRUSTED_CIDRS', '0.0.0.0/0,::/0')}`);
  logger.info(`[trustedHeaderAuth] Max hops: ${env('MAX_HOPS', '1')}`);
  logger.info(`[trustedHeaderAuth] Trust unsigned: ${trustUnsigned}`);
  logger.info(
    `[trustedHeaderAuth] Allow domains: `
    + `${env('ALLOW_DOMAINS') ?? '* (all)'}`,
  );

  if (trustUnsigned && !cidrStrict) {
    logger.error(
      '[trustedHeaderAuth] MISCONFIGURATION: TRUST_UNSIGNED=true requires '
      + 'TRUSTED_HEADER_AUTH_TRUSTED_CIDRS to be set to a specific proxy IP/subnet '
      + '(not 0.0.0.0/0 or unset). Unsigned headers will be rejected at runtime. '
      + 'Fix: set TRUSTED_HEADER_AUTH_TRUSTED_CIDRS=<proxy-subnet>.',
    );
  } else if (trustUnsigned) {
    logger.warn(
      '[trustedHeaderAuth] WARNING: Unsigned headers are trusted. '
      + 'Ensure LibreChat is behind a proxy that overwrites identity headers.',
    );
  }

  if (signers.length === 0 && !trustUnsigned) {
    logger.error(
      '[trustedHeaderAuth] ERROR: No JWT signers configured '
      + 'and TRUST_UNSIGNED is false. No authentication source is available.',
    );
    return;
  }

  if (signers.length === 0) {
    return;
  }

  const isMulti = signers.length > 1;
  const globalClaims = isEnabled(env('JWKS_GLOBAL_CLAIMS_FALLBACK', 'false'));

  if (isMulti) {
    logger.info(
      `[trustedHeaderAuth] Multi-signer mode: ${signers.length} signers configured`,
    );
    logger.info(
      `[trustedHeaderAuth] Global claims fallback: ${globalClaims ? 'enabled' : 'disabled'}`,
    );
  }

  for (const signer of signers) {
    const source = signer.uri ? `JWKS: ${signer.uri}` : 'Static PEM key';
    logger.info(`[trustedHeaderAuth] Signer ${signer.index}: ${source}`);
    logger.info(
      `[trustedHeaderAuth]   Algorithms: ${signer.algorithms.join(', ')}`,
    );
    logger.info(
      `[trustedHeaderAuth]   Issuer: ${signer.issuer ?? '(any)'}`,
    );
    logger.info(
      `[trustedHeaderAuth]   Audience: ${signer.audience ?? '(any)'}`,
    );
    logger.info(
      `[trustedHeaderAuth]   Claims: sub=${signer.claims.sub}, `
      + `email=${signer.claims.email}, `
      + `username=${signer.claims.username}, `
      + `name=${signer.claims.name}, `
      + `picture=${signer.claims.picture}, `
      + `emailVerified=${signer.claims.emailVerified}`,
    );
    logger.info(
      `[trustedHeaderAuth]   Assume email verified (when claim absent): `
      + `${signer.assumeVerified}`,
    );
  }
}
