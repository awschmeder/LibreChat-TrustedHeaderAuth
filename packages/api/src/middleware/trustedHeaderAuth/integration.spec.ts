/**
 * Integration test: exercises the full chain from middleware factory through
 * extractClaims to real RSA JWT verification, without mocking crypto.
 */
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';
import type { IUser } from '@librechat/data-schemas';
import { initSigners, resetSigners } from './signers';
import { resetJwksCache, getCachedOrExtractClaims, getJwksCacheSize } from './jwksCache';
import { createTrustedHeaderAuthMiddleware, HEADER_AUTH_PROVIDER } from './index';
import { buildDeps, buildReq, buildRes } from './testHelpers';

const envKeys = [
  'TRUSTED_HEADER_AUTH_ENABLED',
  'TRUSTED_HEADER_AUTH_TRUST_UNSIGNED',
  'TRUSTED_HEADER_AUTH_TRUSTED_CIDRS',
  'TRUSTED_HEADER_AUTH_JWT_HEADER',
  'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWT_JWKS_URI',
  'TRUSTED_HEADER_AUTH_JWT_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWT_ISSUER',
  'TRUSTED_HEADER_AUTH_JWT_AUDIENCE',
  'TRUSTED_HEADER_AUTH_ALLOW_DOMAINS',
  'TRUSTED_HEADER_AUTH_ASSUME_EMAIL_VERIFIED',
  'TRUSTED_HEADER_AUTH_USERINFO_HEADER',
  'TRUSTED_HEADER_AUTH_EMAIL_HEADER',
  'TRUSTED_HEADER_AUTH_JWKS_CACHE_MAX_ENTRIES',
];

let rsaKeyPair: { publicKey: string; privateKey: string };

beforeAll(() => {
  rsaKeyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
});

const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of envKeys) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  resetSigners();
  resetJwksCache();
});

afterEach(() => {
  for (const key of envKeys) {
    if (savedEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = savedEnv[key];
    }
  }
  resetSigners();
  resetJwksCache();
});

describe('integration: real RSA JWT verification through middleware', () => {
  it('authenticates a user with a real RSA-signed JWT end-to-end', async () => {
    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaKeyPair.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';

    const tokenPayload = {
      sub: 'real-user-sub-123',
      email: 'alice@example.com',
      preferred_username: 'alice',
      name: 'Alice Wonderland',
      picture: 'https://example.com/alice.png',
      email_verified: true,
    };

    const signedJwt = jwt.sign(tokenPayload, rsaKeyPair.privateKey, {
      algorithm: 'RS256',
      expiresIn: '5m',
    });

    const deps = buildDeps();
    const middleware = createTrustedHeaderAuthMiddleware(deps) as (
      req: Request,
      res: Response,
      next: NextFunction,
    ) => Promise<void>;

    // No existing user -- middleware should create one
    deps.findUser.mockResolvedValue(null);
    deps.isEnabled.mockReturnValue(true);
    deps.getBalanceConfig.mockReturnValue({});

    const createdUser = {
      _id: 'new-user-id',
      email: 'alice@example.com',
      provider: HEADER_AUTH_PROVIDER,
    } as unknown as IUser;
    deps.createUser.mockResolvedValue(createdUser);
    deps.setAuthTokens.mockResolvedValue('session-token');

    const req = buildReq({
      ip: '10.0.0.5',
      headers: {
        'x-id-token': signedJwt,
        'sec-fetch-mode': 'navigate',
        accept: 'text/html',
      },
    });
    const res = buildRes();
    const next = jest.fn();

    await middleware(req, res, next);

    // Verify the user was created with claims extracted from the real JWT
    expect(deps.createUser).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'real-user-sub-123',
        email: 'alice@example.com',
        username: 'alice',
        name: 'Alice Wonderland',
        emailVerified: true,
        avatar: 'https://example.com/alice.png',
      }),
      expect.anything(),
      true,
      true,
    );
    expect(deps.setAuthTokens).toHaveBeenCalledWith('new-user-id', res);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('rejects a JWT signed with a different key', async () => {
    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaKeyPair.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';

    // Sign with a different private key
    const wrongKey = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const signedJwt = jwt.sign(
      { sub: 'attacker', email: 'evil@example.com' },
      wrongKey.privateKey,
      { algorithm: 'RS256' },
    );

    const deps = buildDeps();
    const middleware = createTrustedHeaderAuthMiddleware(deps) as (
      req: Request,
      res: Response,
      next: NextFunction,
    ) => Promise<void>;

    const req = buildReq({
      ip: '10.0.0.5',
      headers: {
        'x-id-token': signedJwt,
        'sec-fetch-mode': 'navigate',
        accept: 'text/html',
      },
    });
    const res = buildRes();
    const next = jest.fn();

    await middleware(req, res, next);

    // Invalid JWT should result in no authentication (next called, no user created)
    expect(deps.createUser).not.toHaveBeenCalled();
    expect(deps.setAuthTokens).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
  });
});

describe('JWKS claims cache', () => {
  function signJwt(payload: Record<string, unknown>): string {
    return jwt.sign(payload, rsaKeyPair.privateKey, {
      algorithm: 'RS256',
      expiresIn: '5m',
    });
  }

  function makeJwtReq(token: string): Request {
    return buildReq({
      headers: { 'x-id-token': token },
    });
  }

  beforeEach(() => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaKeyPair.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';
  });

  it('uses JWT signature segment as cache key (not full token)', async () => {
    const token = signJwt({ sub: 'u1', email: 'a@b.com' });
    const req = makeJwtReq(token);

    await getCachedOrExtractClaims(req, initSigners());
    expect(getJwksCacheSize()).toBe(1);

    // Second call with same token should hit cache (no error, same result)
    const result = await getCachedOrExtractClaims(req, initSigners());
    expect(result).not.toBeNull();
    expect(result?.email).toBe('a@b.com');
    expect(getJwksCacheSize()).toBe(1);
  });

  it('caches distinct tokens separately', async () => {
    const token1 = signJwt({ sub: 'u1', email: 'a@b.com' });
    const token2 = signJwt({ sub: 'u2', email: 'c@d.com' });

    await getCachedOrExtractClaims(makeJwtReq(token1), initSigners());
    await getCachedOrExtractClaims(makeJwtReq(token2), initSigners());
    expect(getJwksCacheSize()).toBe(2);
  });

  it('hard-evicts oldest entries when cache exceeds max entries', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_CACHE_MAX_ENTRIES = '3';

    const tokens = Array.from({ length: 5 }, (_, i) =>
      signJwt({ sub: `user-${i}`, email: `u${i}@test.com` }),
    );

    for (const token of tokens) {
      const signers = initSigners();
      resetSigners();
      await getCachedOrExtractClaims(makeJwtReq(token), signers, { jwksCacheMaxEntries: 3 } as never);
    }

    // Hard cap is 3 -- cache should never exceed it after a prune
    expect(getJwksCacheSize()).toBeLessThanOrEqual(3);
  });

  it('bypasses cache for unsigned userinfo headers (no dots in header)', async () => {
    // Remove JWT signer config so the unsigned path is used
    delete process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY;
    delete process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS;
    resetSigners();

    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';

    const payload = Buffer.from(
      JSON.stringify({ sub: 'u1', email: 'user@example.com', preferred_username: 'user', name: 'User' }),
    ).toString('base64');

    const req = buildReq({
      ip: '10.0.0.5',
      headers: { 'x-userinfo': payload },
    });

    const result = await getCachedOrExtractClaims(req, initSigners(), {
      trustUnsigned: true,
      jwtHeader: 'X-Id-Token',
      userinfoHeader: 'X-Userinfo',
      emailHeader: 'X-Forwarded-Email',
      assumeEmailVerified: false,
      jwksFallbackSequential: false,
      jwksCacheMaxEntries: 1000,
    });

    expect(result).not.toBeNull();
    expect(result?.email).toBe('user@example.com');
    // Cache should remain empty -- unsigned path does not populate it
    expect(getJwksCacheSize()).toBe(0);
  });

  it('respects JWKS_CACHE_MAX_ENTRIES env var', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_CACHE_MAX_ENTRIES = '2';

    const tokens = Array.from({ length: 4 }, (_, i) =>
      signJwt({ sub: `user-${i}`, email: `u${i}@test.com` }),
    );

    for (const token of tokens) {
      const signers = initSigners();
      resetSigners();
      await getCachedOrExtractClaims(makeJwtReq(token), signers, { jwksCacheMaxEntries: 2 } as never);
    }

    expect(getJwksCacheSize()).toBeLessThanOrEqual(2);
  });

  it('resetJwksCache clears the cache completely', async () => {
    const token = signJwt({ sub: 'u1', email: 'a@b.com' });
    await getCachedOrExtractClaims(makeJwtReq(token), initSigners());
    expect(getJwksCacheSize()).toBe(1);

    resetJwksCache();
    expect(getJwksCacheSize()).toBe(0);
  });
});
