import type { Request, Response } from 'express';
import type { HeaderAuthDeps, FrozenConfig } from './types';

/** Return type for buildDeps -- HeaderAuthDeps with all fields typed as jest.Mock. */
export type MockedDeps = HeaderAuthDeps & {
  findUser: jest.Mock;
  createUser: jest.Mock;
  updateUser: jest.Mock;
  getUserById: jest.Mock;
  deleteSession: jest.Mock;
  setAuthTokens: jest.Mock;
  getAppConfig: jest.Mock;
  isEnabled: jest.Mock;
  getBalanceConfig: jest.Mock;
};

/** Build a mock HeaderAuthDeps with all functions as jest.Mock instances. */
export function buildDeps(): MockedDeps {
  return {
    findUser: jest.fn(),
    createUser: jest.fn(),
    updateUser: jest.fn(),
    getUserById: jest.fn(),
    deleteSession: jest.fn(),
    setAuthTokens: jest.fn(),
    getAppConfig: jest.fn().mockResolvedValue({}),
    isEnabled: jest.fn().mockReturnValue(true),
    getBalanceConfig: jest.fn().mockReturnValue({}),
  };
}

/**
 * Minimal subset of Express Request used by the middleware.
 * Avoids the `as unknown as Request` double cast in tests.
 */
export interface MockRequest {
  method: string;
  path: string;
  originalUrl: string;
  ip: string;
  cookies: Record<string, string>;
  headers: Record<string, string>;
}

/** Build a mock Express Request with sensible defaults for trusted header auth tests. */
export function buildReq(
  overrides: Partial<MockRequest> = {},
): MockRequest & Request {
  return {
    method: 'GET',
    path: '/',
    originalUrl: '/',
    ip: '10.0.0.1',
    cookies: overrides.cookies ?? {},
    headers: {
      'sec-fetch-mode': 'navigate',
      accept: 'text/html',
      ...overrides.headers,
    },
    ...overrides,
  } as MockRequest & Request;
}

/**
 * Create a lazy Proxy-based readAllConfig mock so per-test env var
 * changes are visible through the frozen config object.
 *
 * Designed for use inside jest.mock('./env', ...) blocks.
 */
export function createLazyConfigMock(
  actual: { env: (suffix: string, fallback?: string) => string | undefined },
  mockIsEnabled: (v: string | undefined) => boolean,
): (isEnabledFn?: (v: string | undefined) => boolean) => Readonly<FrozenConfig> {
  return (isEnabledFn?: (v: string | undefined) => boolean) => {
    const fn = isEnabledFn ?? mockIsEnabled;
    const { env } = actual;
    const readers: Record<string, () => unknown> = {
      trustedCidrs: () => env('TRUSTED_CIDRS', '0.0.0.0/0,::/0'),
      maxHops: () => parseInt(env('MAX_HOPS', '1') as string, 10),
      trustUnsigned: () => fn(env('TRUST_UNSIGNED', 'false')),
      assumeEmailVerified: () => fn(env('ASSUME_EMAIL_VERIFIED', 'false')),
      jwtHeader: () => env('JWT_HEADER', 'X-Id-Token'),
      userinfoHeader: () => env('USERINFO_HEADER', 'X-Userinfo'),
      emailHeader: () => env('EMAIL_HEADER', 'X-Forwarded-Email'),
      allowDomains: () => env('ALLOW_DOMAINS', '*'),
      parsedAllowDomains: () => {
        const raw = env('ALLOW_DOMAINS', '*') as string;
        return raw.trim() === '*'
          ? new Set<string>()
          : new Set(raw.split(',').map((d) => d.trim().toLowerCase()).filter(Boolean));
      },
      jwksCacheMaxEntries: () => parseInt(env('JWKS_CACHE_MAX_ENTRIES', '1000') as string, 10),
    };
    return new Proxy({}, {
      get(_target, prop: string) {
        return readers[prop]?.();
      },
    }) as unknown as Readonly<FrozenConfig>;
  };
}

/** Build a mock Express Response with status, send, json, cookie, clearCookie mocks. */
export function buildRes(): Response {
  const res = {
    status: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    clearCookie: jest.fn().mockReturnThis(),
    cookie: jest.fn().mockReturnThis(),
  };
  return res as unknown as Response;
}
