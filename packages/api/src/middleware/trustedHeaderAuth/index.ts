import jwt from 'jsonwebtoken';
import { logger } from '@librechat/data-schemas';
import type { RequestHandler, Request, Response, NextFunction } from 'express';
import type { IUser, BalanceConfig } from '@librechat/data-schemas';
import type { HeaderAuthDeps, HeaderAuthClaims, UserProfileUpdates, FrozenConfig, JwksSigner, RefreshTokenPayload } from './types';
import { extractClaims as extractClaimsInternal } from './claims';
import { getCachedOrExtractClaims } from './jwksCache';
import { isSourceTrusted } from './network';
import { initSigners } from './signers';
import { getCachedConfig, readAllConfig, env } from './env';
import { logConfig } from './logConfig';
import { redactEmail } from './utils';
export { redactEmail } from './utils';

/**
 * Extracts claims from the request without caching. Used at refresh-token
 * time where caching is unnecessary since this path runs infrequently.
 */
export async function extractClaims(req: Request): Promise<HeaderAuthClaims | null> {
  const signers = initSigners();
  const config = getCachedConfig();
  return extractClaimsInternal(req, signers, config);
}

export const HEADER_AUTH_PROVIDER = 'header-auth';

const CLAIMS_CACHE_KEY = '_trustedHeaderClaims';

interface CachedClaimsRequest extends Request {
  [CLAIMS_CACHE_KEY]?: HeaderAuthClaims | null;
}

/** Return cached claims from a prior call within this request, or extract and cache them. */
async function getCachedClaims(
  req: CachedClaimsRequest,
  signers: JwksSigner[],
  config: FrozenConfig,
): Promise<HeaderAuthClaims | null> {
  if (CLAIMS_CACHE_KEY in req) {
    return req[CLAIMS_CACHE_KEY] as HeaderAuthClaims | null;
  }
  const claims = await getCachedOrExtractClaims(req, signers, config);
  req[CLAIMS_CACHE_KEY] = claims;
  return claims;
}

/** Convert a claim value to a lowercase alphanumeric username string. */
function convertToUsername(input: string, defaultValue = ''): string {
  return input.toLowerCase().replace(/[^a-z0-9]/g, '_') || defaultValue;
}

/**
 * Remove auth cookies so the SPA detects no session.
 * Note: this is a brittle dependency on cookie names set by
 * setAuthTokens/setOpenIDAuthTokens in api/server/services/AuthService.js.
 * Keep in sync if those cookie names ever change.
 */
function clearAuthCookies(res: Response): void {
  res.clearCookie('refreshToken');
  res.clearCookie('token_provider');
}

/** Read the refreshToken cookie populated by cookie-parser middleware. */
function getRefreshToken(req: Request): string | null {
  return (req.cookies?.refreshToken as string | undefined) ?? null;
}

/**
 * Enforce session validity for header-auth users on page navigations.
 *
 * When a refreshToken cookie exists, re-validates identity headers via
 * extractClaims(). If claims are absent or invalid, decodes the refresh
 * token to identify the user. If the user's provider is 'header-auth',
 * the MongoDB session is deleted (making the refresh token permanently
 * dead) and cookies are cleared.
 *
 * Non-header-auth users (local, OpenID) are never affected.
 *
 * @returns true if the request should skip to next()
 *   (either session is valid or cookies were cleared); false if no
 *   existing auth was found (proceed with normal header auth flow).
 */
async function enforceExistingSession(
  req: Request,
  res: Response,
  deps: HeaderAuthDeps,
  signers: JwksSigner[],
  config: FrozenConfig,
): Promise<boolean> {
  if (!isSourceTrusted(req, config)) {
    logger.warn('[trustedHeaderAuth] Request from untrusted source during session enforcement');
    return true;
  }

  const refreshToken = getRefreshToken(req);
  if (!refreshToken) {
    // Race condition: a session may be created between this check and the
    // response. This is expected and benign -- we prefer allowing the
    // request through over adding a DB query to every cookieless request.
    return false;
  }

  const claims = await getCachedClaims(req, signers, config);
  if (claims && claims.email) {
    return true;
  }

  const payload = jwt.decode(refreshToken) as RefreshTokenPayload | null;

  if (!payload || !payload.id) {
    clearAuthCookies(res);
    return true;
  }

  let user;
  try {
    user = await deps.getUserById(payload.id, 'provider');
  } catch (err) {
    logger.error('[trustedHeaderAuth] DB lookup failed during session enforcement:', err);
    return true;
  }

  if (!user || user.provider !== HEADER_AUTH_PROVIDER) {
    return true;
  }

  logger.warn(
    `[trustedHeaderAuth] Identity headers absent/invalid for `
    + `header-auth user ${user.email ? redactEmail(user.email) : payload.id}; `
    + `terminating session`,
  );

  if (payload.sessionId) {
    try {
      await deps.deleteSession({ sessionId: payload.sessionId });
    } catch (err) {
      logger.error('[trustedHeaderAuth] Failed to delete session:', err);
    }
  }

  clearAuthCookies(res);
  return true;
}

/**
 * Find an existing user by openidId (sub claim) with header-auth provider.
 * If sub changes for the same email within header-auth, update the openidId.
 */
async function findHeaderAuthUser(
  sub: string,
  email: string,
  deps: HeaderAuthDeps,
): Promise<IUser | null> {
  if (sub) {
    const user = await deps.findUser({ openidId: sub, provider: HEADER_AUTH_PROVIDER });
    if (user) {
      return user;
    }
  }

  if (email) {
    const user = await deps.findUser({ email: email.trim().toLowerCase(), provider: HEADER_AUTH_PROVIDER });
    if (user) {
      return user;
    }
  }

  return null;
}

/**
 * Build the profile update object for an existing user.
 * Includes openidId update in case sub claim changed for same user.
 * Only includes fields that differ from the current user record.
 */
function buildProfileUpdates(
  claims: HeaderAuthClaims,
  existingUser: { name?: string; username?: string; email?: string; emailVerified?: boolean; avatar?: string; openidId?: string },
): UserProfileUpdates {
  const updates: UserProfileUpdates = {};

  if (claims.sub && claims.sub !== existingUser.openidId) {
    updates.openidId = claims.sub;
  }

  if (claims.name && claims.name !== existingUser.name) {
    updates.name = claims.name;
  }
  const username = convertToUsername(claims.username);
  if (username && username !== existingUser.username) {
    updates.username = username;
  }
  if (claims.email.toLowerCase() !== existingUser.email?.toLowerCase()) {
    updates.email = claims.email;
  }
  if (claims.emailVerified !== existingUser.emailVerified) {
    updates.emailVerified = claims.emailVerified;
  }
  if (claims.picture && claims.picture !== existingUser.avatar) {
    updates.avatar = claims.picture;
  }

  return updates;
}

/**
 * Create the Express middleware function.
 *
 * Registered globally for maximum coverage -- the early-return path for
 * requests without identity headers is near-zero cost (no DB queries,
 * no async work beyond a header check).
 *
 * All DB and service calls are provided via `deps` so this module has no
 * direct coupling to ~/models or ~/server/services.
 */
export function createTrustedHeaderAuthMiddleware(deps: HeaderAuthDeps): RequestHandler {
  const signers = initSigners();
  logConfig(signers);
  const config = readAllConfig(deps.isEnabled);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let claims: HeaderAuthClaims | null = null;
    try {
      const handled = await enforceExistingSession(req, res, deps, signers, config);
      if (handled) {
        next();
        return;
      }

      if (!isSourceTrusted(req, config)) {
        next();
        return;
      }

      claims = await getCachedClaims(req, signers, config);
      if (!claims || !claims.email) {
        next();
        return;
      }

      const normalizedEmail = claims.email.toLowerCase();

      if (config.parsedAllowDomains.size > 0) {
        const emailDomain = normalizedEmail.split('@')[1];
        if (!emailDomain || !config.parsedAllowDomains.has(emailDomain)) {
          logger.warn(`[trustedHeaderAuth] Email domain not allowed: ${redactEmail(normalizedEmail)}`);
          res.status(403).send('Email domain not allowed');
          return;
        }
      }

      const normalizedClaims = { ...claims, email: normalizedEmail };

      const existingUser = await findHeaderAuthUser(
        normalizedClaims.sub,
        normalizedClaims.email,
        deps,
      );

      let user;

      if (existingUser) {
        const updates = buildProfileUpdates(normalizedClaims, existingUser);
        if (Object.keys(updates).length > 0) {
          await deps.updateUser(String(existingUser._id), updates);
        }
        user = existingUser;
      } else {
        const autoCreate = deps.isEnabled(
          env('NEW_USER_AUTO_CREATE', 'true'),
        );
        if (!autoCreate) {
          logger.warn(`[trustedHeaderAuth] Auto-create disabled, rejecting: ${redactEmail(normalizedClaims.email)}`);
          res.status(403).send('Account does not exist');
          return;
        }

        const appConfig = await deps.getAppConfig();
        const balanceConfig = deps.getBalanceConfig(appConfig);
        const username = convertToUsername(normalizedClaims.username) || normalizedClaims.email.split('@')[0];

        const newUserData = {
          provider: HEADER_AUTH_PROVIDER,
          openidId: normalizedClaims.sub,
          email: normalizedClaims.email,
          username,
          name: normalizedClaims.name || username,
          emailVerified: normalizedClaims.emailVerified,
          avatar: normalizedClaims.picture || null,
        };

        const emptyBalance: BalanceConfig = {};
        user = await deps.createUser(newUserData, balanceConfig ?? emptyBalance, true, true);
        logger.info(`[trustedHeaderAuth] Created new user: ${redactEmail(normalizedClaims.email)} (${user._id})`);
      }

      // Cookieless request -- enforceExistingSession already returned for authenticated sessions.
      // Skip session creation for non-navigation requests (XHR/fetch/WebSocket) to prevent
      // MongoDB session leaks when cookies are blocked by the browser.
      const fetchMode = req.headers['sec-fetch-mode'];
      if (fetchMode != null && fetchMode !== 'navigate') {
        logger.warn('[trustedHeaderAuth] Non-navigation request without session cookie; skipping session creation');
        return next();
      }

      await deps.setAuthTokens(String(user._id), res);

      logger.info(`[trustedHeaderAuth] Authenticated: ${redactEmail(user.email)} (${user._id})`);

      next();
    } catch (err) {
      logger.error('[trustedHeaderAuth] Middleware error:', err);
      // If claims were successfully extracted, an error during authenticated
      // processing (user lookup, token generation) should fail the request
      // rather than silently falling through to unauthenticated state.
      if (claims) {
        res.status(500).json({ error: 'Internal authentication error' });
        return;
      }
      next();
    }
  };
}
