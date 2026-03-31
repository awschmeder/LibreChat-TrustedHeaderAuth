import jwt from 'jsonwebtoken';
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

describe('trustedHeaderAuth session enforcement', () => {
  let deps: ReturnType<typeof buildDeps>;
  let middleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;

  beforeEach(() => {
    jest.clearAllMocks();
    deps = buildDeps();
    middleware = createTrustedHeaderAuthMiddleware(deps) as typeof middleware;
    mockIsSourceTrusted.mockReturnValue(true);
  });

  describe('enforceExistingSession', () => {
    it('allows request through when refreshToken exists and extractClaims returns valid claims', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: '',
        emailVerified: false,
      });

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.clearCookie).not.toHaveBeenCalled();
      expect(deps.deleteSession).not.toHaveBeenCalled();
    });

    it('kills session and clears cookies when extractClaims returns null for header-auth user', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);

      deps.getUserById.mockResolvedValue({
        _id: 'user-123',
        email: 'user@example.com',
        provider: HEADER_AUTH_PROVIDER,
      } as unknown as IUser);

      deps.deleteSession.mockResolvedValue({ deletedCount: 1 });

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.getUserById).toHaveBeenCalledWith('user-123', 'provider');
      expect(deps.deleteSession).toHaveBeenCalledWith({ sessionId: 'session-456' });
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
      expect(res.clearCookie).toHaveBeenCalledWith('token_provider');
      expect(deps.setAuthTokens).not.toHaveBeenCalled();
    });

    it('leaves session intact when extractClaims returns null for non-header-auth user', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);

      deps.getUserById.mockResolvedValue({
        _id: 'user-123',
        email: 'user@example.com',
        provider: 'local',
      } as unknown as IUser);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.deleteSession).not.toHaveBeenCalled();
      expect(res.clearCookie).not.toHaveBeenCalled();
    });

    it('leaves session intact when extractClaims returns null for openid user', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);

      deps.getUserById.mockResolvedValue({
        _id: 'user-123',
        email: 'user@example.com',
        provider: 'openid',
      } as unknown as IUser);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.deleteSession).not.toHaveBeenCalled();
      expect(res.clearCookie).not.toHaveBeenCalled();
    });

    it('clears cookies when refreshToken is malformed (not a valid JWT)', async () => {
      const req = buildReq({
        cookies: { refreshToken: 'not-a-jwt-at-all' },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
      expect(res.clearCookie).toHaveBeenCalledWith('token_provider');
    });

    it('proceeds to normal auth flow when no refreshToken cookie is present', async () => {
      const req = buildReq({
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);
      mockIsSourceTrusted.mockReturnValue(true);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.getUserById).not.toHaveBeenCalled();
    });

    it('handles DB error gracefully during session enforcement', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);
      deps.getUserById.mockRejectedValue(new Error('DB connection lost'));

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.deleteSession).not.toHaveBeenCalled();
    });

    it('handles deleteSession failure gracefully', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);
      deps.getUserById.mockResolvedValue({
        _id: 'user-123',
        email: 'user@example.com',
        provider: HEADER_AUTH_PROVIDER,
      } as unknown as IUser);
      deps.deleteSession.mockRejectedValue(new Error('Session not found'));

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
      expect(res.clearCookie).toHaveBeenCalledWith('token_provider');
    });

    it('runs session enforcement on non-GET requests when a refreshToken is present', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        method: 'POST',
        cookies: { refreshToken },
        headers: {},
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue(null);
      deps.getUserById.mockResolvedValue({
        _id: 'user-123',
        email: 'user@example.com',
        provider: 'local',
      } as unknown as IUser);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(mockExtractClaims).toHaveBeenCalled();
      expect(deps.getUserById).toHaveBeenCalled();
    });

    it('kills session when extractClaims returns claims without email', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: '',
        username: '',
        name: '',
        picture: '',
        emailVerified: false,
      });

      deps.getUserById.mockResolvedValue({
        _id: 'user-123',
        email: 'user@example.com',
        provider: HEADER_AUTH_PROVIDER,
      } as unknown as IUser);

      deps.deleteSession.mockResolvedValue({ deletedCount: 1 });

      await middleware(req, res, next);

      expect(deps.deleteSession).toHaveBeenCalledWith({ sessionId: 'session-456' });
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
    });

    it('catches gracefully when extractClaims throws synchronously during session enforcement', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: {
          'sec-fetch-mode': 'navigate',
        },
      });
      const res = buildRes();
      const next = jest.fn();

      // Force getCachedOrExtractClaims to throw (not reject -- synchronous throw)
      mockExtractClaims.mockImplementation(() => {
        throw new Error('Unexpected synchronous failure');
      });

      await middleware(req, res, next);

      // The outer try/catch in the middleware should handle the thrown error.
      // Since claims were not successfully extracted, it falls through via next().
      expect(next).toHaveBeenCalled();
    });
  });

  describe('CIDR check during session enforcement', () => {
    it('skips session enforcement for requests from untrusted sources', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: { 'sec-fetch-mode': 'navigate' },
      });
      const res = buildRes();
      const next = jest.fn();

      mockIsSourceTrusted.mockReturnValue(false);

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.getUserById).not.toHaveBeenCalled();
      expect(deps.deleteSession).not.toHaveBeenCalled();
      expect(res.clearCookie).not.toHaveBeenCalled();
    });

    it('proceeds with session enforcement for requests from trusted sources', async () => {
      const refreshToken = jwt.sign(
        { id: 'user-123', sessionId: 'session-456' },
        'test-secret',
      );
      const req = buildReq({
        cookies: { refreshToken },
        headers: { 'sec-fetch-mode': 'navigate' },
      });
      const res = buildRes();
      const next = jest.fn();

      mockIsSourceTrusted.mockReturnValue(true);
      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: '',
        emailVerified: false,
      });

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(deps.deleteSession).not.toHaveBeenCalled();
      expect(res.clearCookie).not.toHaveBeenCalled();
    });
  });

  describe('profile sync on returning user (no migration)', () => {
    it('updates name, username, email, and avatar when claims differ', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'new@example.com',
        username: 'newuser',
        name: 'New Name',
        picture: 'https://example.com/avatar.png',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'old@example.com',
        username: 'olduser',
        name: 'Old Name',
        avatar: null,
      } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.updateUser).toHaveBeenCalledWith('user-123', {
        name: 'New Name',
        username: 'newuser',
        email: 'new@example.com',
        emailVerified: true,
        avatar: 'https://example.com/avatar.png',
      });
      expect(next).toHaveBeenCalled();
    });

    it('skips updateUser when all profile fields match', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: 'https://example.com/pic.png',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        avatar: 'https://example.com/pic.png',
        emailVerified: true,
      } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.updateUser).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    it('updates only avatar when other fields match', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: 'https://example.com/new-avatar.png',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        avatar: 'https://example.com/old-avatar.png',
        emailVerified: true,
      } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.updateUser).toHaveBeenCalledWith('user-123', {
        avatar: 'https://example.com/new-avatar.png',
      });
    });
  });

  describe('buildProfileUpdates (tested indirectly via middleware)', () => {
    it('updates emailVerified when it changes but email stays the same', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: 'https://example.com/pic.png',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        avatar: 'https://example.com/pic.png',
        emailVerified: false,
      } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.updateUser).toHaveBeenCalledWith('user-123', {
        emailVerified: true,
      });
      expect(next).toHaveBeenCalled();
    });

    it('does not include picture in updates when claims.picture is empty', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'new@example.com',
        username: 'newuser',
        name: 'New Name',
        picture: '',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'old@example.com',
        username: 'olduser',
        name: 'Old Name',
        avatar: 'https://example.com/old.png',
        emailVerified: false,
      } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      const updateCall = deps.updateUser.mock.calls[0][1];
      expect(updateCall).not.toHaveProperty('avatar');
      expect(updateCall).toEqual(expect.objectContaining({
        email: 'new@example.com',
        username: 'newuser',
        name: 'New Name',
        emailVerified: true,
      }));
    });

    it('skips updateUser when all fields match including emailVerified', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: 'https://example.com/pic.png',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        avatar: 'https://example.com/pic.png',
        emailVerified: true,
      } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.updateUser).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    it('updates openidId when sub claim changes for same email', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'new-sub-456',
        email: 'user@example.com',
        username: 'testuser',
        name: 'Test User',
        picture: 'https://example.com/pic.png',
        emailVerified: true,
      });

      // findUser by openidId returns null (sub changed), then by email returns the user
      deps.findUser
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({
          _id: 'user-123',
          provider: HEADER_AUTH_PROVIDER,
          openidId: 'old-sub-123',
          email: 'user@example.com',
          username: 'testuser',
          name: 'Test User',
          avatar: 'https://example.com/pic.png',
          emailVerified: true,
        } as unknown as IUser);

      deps.setAuthTokens.mockResolvedValue('token-abc');

      await middleware(req, res, next);

      expect(deps.updateUser).toHaveBeenCalledWith('user-123', {
        openidId: 'new-sub-456',
      });
      expect(next).toHaveBeenCalled();
    });

    it('returns 500 when updateUser rejects during profile sync', async () => {
      const req = buildReq();
      const res = buildRes();
      const next = jest.fn();

      mockExtractClaims.mockResolvedValue({
        sub: 'sub-123',
        email: 'new@example.com',
        username: 'newuser',
        name: 'New Name',
        picture: 'https://example.com/avatar.png',
        emailVerified: true,
      });

      deps.findUser.mockResolvedValueOnce({
        _id: 'user-123',
        provider: HEADER_AUTH_PROVIDER,
        openidId: 'sub-123',
        email: 'old@example.com',
        username: 'olduser',
        name: 'Old Name',
        avatar: null,
      } as unknown as IUser);

      deps.updateUser.mockRejectedValue(new Error('DB write failed'));

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Internal authentication error' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
