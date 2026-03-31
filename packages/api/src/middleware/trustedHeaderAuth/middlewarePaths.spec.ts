import type { Request, Response, NextFunction } from 'express';
import type { IUser } from '@librechat/data-schemas';
import { buildDeps, buildReq, buildRes } from './testHelpers';

jest.mock('./claims', () => ({
  extractClaims: jest.fn(),
}));

jest.mock('./jwksCache', () => ({
  getCachedOrExtractClaims: jest.fn(),
  resetJwksCache: jest.fn(),
  getJwksCacheSize: jest.fn().mockReturnValue(0),
}));

jest.mock('./network', () => ({
  isSourceTrusted: jest.fn().mockReturnValue(true),
  isCidrStrict: jest.fn(),
  parseCidr: jest.fn(),
  ipv4InCidr: jest.fn(),
  ipv6InCidr: jest.fn(),
}));

jest.mock('./logConfig', () => ({
  logConfig: jest.fn(),
}));

jest.mock('./env', () => {
  const actual = jest.requireActual('./env');
  const { isEnabled: mockIsEnabled } = jest.requireActual('~/utils');
  const { createLazyConfigMock } = jest.requireActual('./testHelpers');
  return {
    ...actual,
    readAllConfig: createLazyConfigMock(actual, mockIsEnabled),
  };
});

import { getCachedOrExtractClaims } from './jwksCache';
import { isSourceTrusted } from './network';
import { createTrustedHeaderAuthMiddleware, HEADER_AUTH_PROVIDER } from './index';

const mockExtractClaims = getCachedOrExtractClaims as jest.MockedFunction<typeof getCachedOrExtractClaims>;
const mockIsSourceTrusted = isSourceTrusted as jest.MockedFunction<typeof isSourceTrusted>;

const validClaims = {
  sub: 'sub-new',
  email: 'newuser@example.com',
  username: 'newuser',
  name: 'New User',
  picture: 'https://example.com/pic.png',
  emailVerified: true,
};

describe('trustedHeaderAuth middleware paths', () => {
  let deps: ReturnType<typeof buildDeps>;
  let middleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;

  beforeEach(() => {
    jest.clearAllMocks();
    deps = buildDeps();
    middleware = createTrustedHeaderAuthMiddleware(deps) as typeof middleware;
    mockIsSourceTrusted.mockReturnValue(true);
  });

  // -----------------------------------------------------------------------
  // Domain filtering
  // -----------------------------------------------------------------------

  describe('domain filtering', () => {
    let origAllowDomains: string | undefined;

    beforeEach(() => {
      origAllowDomains = process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS;
    });

    afterEach(() => {
      if (origAllowDomains === undefined) {
        delete process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS;
      } else {
        process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS = origAllowDomains;
      }
    });

    it('returns 403 when email domain is not in ALLOW_DOMAINS', async () => {
      process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS = 'allowed.com';

      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Email domain not allowed');
      expect(next).not.toHaveBeenCalled();
    });

    it('allows all domains when ALLOW_DOMAINS is * (default)', async () => {
      process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS = '*';

      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      const mockUser = { _id: 'new-1', email: validClaims.email } as unknown as IUser;
      deps.createUser.mockResolvedValue(mockUser);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(res.status).not.toHaveBeenCalledWith(403);
      expect(next).toHaveBeenCalled();
    });

    it('allows all domains when ALLOW_DOMAINS is unset', async () => {
      delete process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS;

      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      const mockUser = { _id: 'new-1', email: validClaims.email } as unknown as IUser;
      deps.createUser.mockResolvedValue(mockUser);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(res.status).not.toHaveBeenCalledWith(403);
      expect(next).toHaveBeenCalled();
    });

    it('allows request when email domain is in the comma-separated allowlist', async () => {
      process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS = 'other.com, example.com, third.com';

      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      const mockUser = { _id: 'new-1', email: validClaims.email } as unknown as IUser;
      deps.createUser.mockResolvedValue(mockUser);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(res.status).not.toHaveBeenCalledWith(403);
      expect(next).toHaveBeenCalled();
    });

    it('performs case-insensitive domain matching', async () => {
      process.env.TRUSTED_HEADER_AUTH_ALLOW_DOMAINS = 'Example.COM';

      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      const mockUser = { _id: 'new-1', email: validClaims.email } as unknown as IUser;
      deps.createUser.mockResolvedValue(mockUser);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(res.status).not.toHaveBeenCalledWith(403);
      expect(next).toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // Auto-create disabled
  // -----------------------------------------------------------------------

  describe('auto-create disabled', () => {
    it('returns 403 when auto-create is disabled and user does not exist', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);

      // Domain filter passes, auto-create is false
      deps.isEnabled.mockImplementation((val: string | undefined) => {
        if (val === 'true') {
          return true;
        }
        if (val === 'false') {
          return false;
        }
        return true;
      });
      const origAutoCreate = process.env.TRUSTED_HEADER_AUTH_NEW_USER_AUTO_CREATE;
      process.env.TRUSTED_HEADER_AUTH_NEW_USER_AUTO_CREATE = 'false';

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Account does not exist');
      expect(deps.createUser).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();

      if (origAutoCreate === undefined) {
        delete process.env.TRUSTED_HEADER_AUTH_NEW_USER_AUTO_CREATE;
      } else {
        process.env.TRUSTED_HEADER_AUTH_NEW_USER_AUTO_CREATE = origAutoCreate;
      }
    });

    it('still authenticates existing users when auto-create is disabled', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);

      const existingUser = {
        _id: 'existing-1',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-new',
        email: 'newuser@example.com',
        username: 'newuser',
        name: 'New User',
        avatar: 'https://example.com/pic.png',
      } as unknown as IUser;
      deps.findUser.mockResolvedValueOnce(existingUser);
      deps.isEnabled.mockReturnValue(true);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.createUser).not.toHaveBeenCalled();
      expect(deps.setAuthTokens).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // New user creation
  // -----------------------------------------------------------------------

  describe('new user creation', () => {
    it('creates a new user with correct profile data', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);
      deps.getBalanceConfig.mockReturnValue({ startingBalance: 100 });

      const createdUser = {
        _id: 'created-1',
        email: validClaims.email,
        provider: HEADER_AUTH_PROVIDER,
      } as unknown as IUser;
      deps.createUser.mockResolvedValue(createdUser);
      deps.setAuthTokens.mockResolvedValue('new-token');

      await middleware(req, res, next);

      expect(deps.createUser).toHaveBeenCalledWith(
        {
          provider: HEADER_AUTH_PROVIDER,
          openidId: validClaims.sub,
          email: validClaims.email,
          username: validClaims.username,
          name: validClaims.name,
          emailVerified: validClaims.emailVerified,
          avatar: validClaims.picture,
        },
        { startingBalance: 100 },
        true,
        true,
      );
      expect(deps.setAuthTokens).toHaveBeenCalledWith(createdUser._id, res);
      expect(next).toHaveBeenCalled();
    });

    it('derives username from email when claim username is empty', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      const claimsNoUsername = { ...validClaims, username: '', name: '' };
      mockExtractClaims.mockResolvedValue(claimsNoUsername);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);

      const createdUser = { _id: 'created-2', email: validClaims.email } as unknown as IUser;
      deps.createUser.mockResolvedValue(createdUser);
      deps.setAuthTokens.mockResolvedValue('new-token');

      await middleware(req, res, next);

      const createCall = deps.createUser.mock.calls[0][0];
      expect(createCall.username).toBe('newuser');
      expect(createCall.name).toBe('newuser');
    });

    it('returns 500 when setAuthTokens throws (claims already extracted)', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);

      const createdUser = { _id: 'created-3', email: validClaims.email } as unknown as IUser;
      deps.createUser.mockResolvedValue(createdUser);
      deps.setAuthTokens.mockRejectedValue(new Error('Token issuance failed'));

      await middleware(req, res, next);

      // Post-claims errors return 500 instead of falling through
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Internal authentication error' });
      expect(next).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // Source trust rejection
  // -----------------------------------------------------------------------

  describe('source trust', () => {
    it('calls next without auth when source is not trusted', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockIsSourceTrusted.mockReturnValue(false);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.setAuthTokens).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // sec-fetch-mode guard
  // -----------------------------------------------------------------------

  describe('sec-fetch-mode guard (cookieless requests)', () => {
    it('creates session for navigate request without cookie', async () => {
      const req = buildReq({
        headers: { 'sec-fetch-mode': 'navigate' },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);
      const createdUser = { _id: 'new-1', email: validClaims.email } as unknown as import('@librechat/data-schemas').IUser;
      deps.createUser.mockResolvedValue(createdUser);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.setAuthTokens).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    it('skips session creation for cors request without cookie', async () => {
      const req = buildReq({
        headers: { 'sec-fetch-mode': 'cors' },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);
      const createdUser = { _id: 'new-1', email: validClaims.email } as unknown as import('@librechat/data-schemas').IUser;
      deps.createUser.mockResolvedValue(createdUser);

      await middleware(req, res, next);

      expect(deps.setAuthTokens).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    it('creates session when sec-fetch-mode header is absent (backwards compat)', async () => {
      const req = buildReq({
        headers: {},
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);
      const createdUser = { _id: 'new-1', email: validClaims.email } as unknown as import('@librechat/data-schemas').IUser;
      deps.createUser.mockResolvedValue(createdUser);
      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.setAuthTokens).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    it('skips session creation for no-cors request without cookie', async () => {
      const req = buildReq({
        headers: { 'sec-fetch-mode': 'no-cors' },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockResolvedValue(null);
      deps.isEnabled.mockReturnValue(true);
      const createdUser = { _id: 'new-1', email: validClaims.email } as unknown as import('@librechat/data-schemas').IUser;
      deps.createUser.mockResolvedValue(createdUser);

      await middleware(req, res, next);

      expect(deps.setAuthTokens).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // Error handling
  // -----------------------------------------------------------------------

  describe('error handling', () => {
    it('passes through when error occurs before claims extraction', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockRejectedValue(new Error('Unexpected error'));

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('returns 500 when error occurs after claims extraction', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(validClaims);
      deps.findUser.mockRejectedValue(new Error('DB connection lost'));

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(next).not.toHaveBeenCalled();
    });
  });
});
