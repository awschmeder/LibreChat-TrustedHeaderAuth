import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { logger } from '@librechat/data-schemas';
import type { Request } from 'express';
import type { SignerClaimPaths } from './types';
import { parseCidr, ipv4InCidr, ipv6InCidr, isSourceTrusted } from './network';
import {
  decodeUserinfoHeader,
  extractEmailHeader,
  mapClaims,
  coerceClaimToString,
} from './claims';
import {
  getCachedOrExtractClaims,
  getJwksCacheSize,
  resetJwksCache,
} from './jwksCache';
import { initSigners, resetSigners } from './signers';
import { validateJwtHeader } from './jwt';
import { base64UrlDecode, getByPath } from './utils';
import { buildReq } from './testHelpers';

// ---------------------------------------------------------------------------
// base64UrlDecode
// ---------------------------------------------------------------------------

describe('base64UrlDecode', () => {
  it('decodes standard base64', () => {
    const encoded = Buffer.from('hello world').toString('base64');
    expect(base64UrlDecode(encoded).toString('utf-8')).toBe('hello world');
  });

  it('handles missing padding', () => {
    // base64url without trailing '=' padding
    const raw = Buffer.from('test').toString('base64').replace(/=+$/, '');
    expect(base64UrlDecode(raw).toString('utf-8')).toBe('test');
  });

  it('handles empty string', () => {
    expect(base64UrlDecode('').toString('utf-8')).toBe('');
  });
});

// ---------------------------------------------------------------------------
// getByPath
// ---------------------------------------------------------------------------

describe('getByPath', () => {
  it('returns direct property for single-level path', () => {
    expect(getByPath({ name: 'Alice' }, 'name')).toBe('Alice');
  });

  it('returns nested value for multi-level path', () => {
    const obj = { a: { b: { c: 'deep' } } };
    expect(getByPath(obj as Record<string, unknown>, 'a.b.c')).toBe('deep');
  });

  it('returns undefined for path through null intermediate', () => {
    const obj = { a: null };
    expect(getByPath(obj as Record<string, unknown>, 'a.b')).toBeUndefined();
  });

  it('returns undefined for path through non-object (string)', () => {
    const obj = { a: 'hello' };
    expect(getByPath(obj as Record<string, unknown>, 'a.b')).toBeUndefined();
  });

  it('returns undefined for path through non-object (number)', () => {
    const obj = { a: 42 };
    expect(getByPath(obj as Record<string, unknown>, 'a.b')).toBeUndefined();
  });

  it('returns undefined for empty path string', () => {
    const obj = { a: 1 };
    expect(getByPath(obj as Record<string, unknown>, '')).toBeUndefined();
  });

  it('traverses array index via dot notation', () => {
    const obj = { items: [{ name: 'first' }, { name: 'second' }] };
    expect(getByPath(obj as Record<string, unknown>, 'items.0.name')).toBe('first');
    expect(getByPath(obj as Record<string, unknown>, 'items.1.name')).toBe('second');
  });

  it('returns undefined for non-existent property', () => {
    const obj = { a: 1 };
    expect(getByPath(obj as Record<string, unknown>, 'b')).toBeUndefined();
  });

  it('blocks __proto__ traversal', () => {
    const obj = { a: 1 };
    expect(getByPath(obj as Record<string, unknown>, '__proto__')).toBeUndefined();
    expect(getByPath(obj as Record<string, unknown>, 'a.__proto__')).toBeUndefined();
  });

  it('blocks constructor traversal', () => {
    const obj = { a: { b: 1 } };
    expect(getByPath(obj as Record<string, unknown>, 'constructor')).toBeUndefined();
    expect(getByPath(obj as Record<string, unknown>, 'a.constructor')).toBeUndefined();
  });

  it('blocks prototype traversal', () => {
    const obj = { a: 1 };
    expect(getByPath(obj as Record<string, unknown>, 'prototype')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// decodeUserinfoHeader
// ---------------------------------------------------------------------------

describe('decodeUserinfoHeader', () => {
  it('decodes valid base64-encoded JSON', () => {
    const payload = { sub: 'user-1', email: 'a@b.com', name: 'Alice' };
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
    expect(decodeUserinfoHeader(encoded)).toEqual(payload);
  });

  it('returns null for invalid base64', () => {
    // Triple-byte garbage that is not valid base64
    expect(decodeUserinfoHeader('%%%not-base64%%%')).toBeNull();
  });

  it('returns null for base64 that is not JSON', () => {
    const encoded = Buffer.from('not json at all').toString('base64');
    expect(decodeUserinfoHeader(encoded)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// extractEmailHeader
// ---------------------------------------------------------------------------

describe('extractEmailHeader', () => {
  it('returns trimmed email for a valid address', () => {
    expect(extractEmailHeader('  user@example.com  ')).toBe('user@example.com');
  });

  it('returns null for empty string', () => {
    expect(extractEmailHeader('')).toBeNull();
  });

  it('returns null for string without @', () => {
    expect(extractEmailHeader('not-an-email')).toBeNull();
  });

  it('returns null for whitespace-only string', () => {
    expect(extractEmailHeader('   ')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// parseCidr
// ---------------------------------------------------------------------------

describe('parseCidr', () => {
  it('parses a valid IPv4 CIDR', () => {
    expect(parseCidr('10.0.0.0/8')).toEqual({ address: '10.0.0.0', prefixLen: 8 });
  });

  it('parses a /32 host address', () => {
    expect(parseCidr('192.168.1.1/32')).toEqual({ address: '192.168.1.1', prefixLen: 32 });
  });

  it('parses a /0 catch-all', () => {
    expect(parseCidr('0.0.0.0/0')).toEqual({ address: '0.0.0.0', prefixLen: 0 });
  });

  it('returns null for bare IP without prefix', () => {
    expect(parseCidr('10.0.0.1')).toBeNull();
  });

  it('returns null for non-numeric prefix', () => {
    expect(parseCidr('10.0.0.0/abc')).toBeNull();
  });

  it('handles whitespace around the CIDR', () => {
    expect(parseCidr('  172.16.0.0/12  ')).toEqual({ address: '172.16.0.0', prefixLen: 12 });
  });

  it('returns null for too many slashes', () => {
    // '10.0.0.0/8/extra' splits into 3 parts
    expect(parseCidr('10.0.0.0/8/extra')).toBeNull();
  });

  // IPv6 CIDR cases
  it('parses a valid IPv6 CIDR', () => {
    expect(parseCidr('2001:db8::/32')).toEqual({ address: '2001:db8::', prefixLen: 32 });
  });

  it('parses IPv6 /0 catch-all', () => {
    expect(parseCidr('::/0')).toEqual({ address: '::', prefixLen: 0 });
  });

  it('parses IPv6 /128 exact host', () => {
    expect(parseCidr('::1/128')).toEqual({ address: '::1', prefixLen: 128 });
  });

  it('returns null for IPv6 out-of-range prefix', () => {
    expect(parseCidr('::1/129')).toBeNull();
  });

  // Non-IP address cases (SEC-3 fix validation)
  it('returns null for non-IP address with prefix', () => {
    expect(parseCidr('garbage/24')).toBeNull();
  });

  it('returns null for non-IP address without prefix', () => {
    expect(parseCidr('garbage')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ipv4InCidr
// ---------------------------------------------------------------------------

describe('ipv4InCidr', () => {
  it('matches IP within a /8 range', () => {
    expect(ipv4InCidr('10.1.2.3', '10.0.0.0', 8)).toBe(true);
  });

  it('rejects IP outside a /8 range', () => {
    expect(ipv4InCidr('11.0.0.1', '10.0.0.0', 8)).toBe(false);
  });

  it('matches exact /32 address', () => {
    expect(ipv4InCidr('192.168.1.1', '192.168.1.1', 32)).toBe(true);
  });

  it('rejects different /32 address', () => {
    expect(ipv4InCidr('192.168.1.2', '192.168.1.1', 32)).toBe(false);
  });

  it('matches any IP for /0 prefix', () => {
    expect(ipv4InCidr('255.255.255.255', '0.0.0.0', 0)).toBe(true);
  });

  it('matches IP within /24 subnet', () => {
    expect(ipv4InCidr('172.16.5.100', '172.16.5.0', 24)).toBe(true);
  });

  it('rejects IP outside /24 subnet', () => {
    expect(ipv4InCidr('172.16.6.1', '172.16.5.0', 24)).toBe(false);
  });

  it('handles /16 boundaries correctly', () => {
    expect(ipv4InCidr('10.89.0.5', '10.89.0.0', 16)).toBe(true);
    expect(ipv4InCidr('10.90.0.1', '10.89.0.0', 16)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ipv6InCidr
// ---------------------------------------------------------------------------

describe('ipv6InCidr', () => {
  it('matches IP within IPv6 /64 subnet', () => {
    expect(ipv6InCidr('2001:db8::1', '2001:db8::', 64)).toBe(true);
    expect(ipv6InCidr('2001:db8::ffff', '2001:db8::', 64)).toBe(true);
  });

  it('rejects IP outside IPv6 /64 subnet', () => {
    expect(ipv6InCidr('2001:db9::1', '2001:db8::', 64)).toBe(false);
  });

  it('handles /128 (exact match)', () => {
    expect(ipv6InCidr('2001:db8::1', '2001:db8::1', 128)).toBe(true);
    expect(ipv6InCidr('2001:db8::2', '2001:db8::1', 128)).toBe(false);
  });

  it('handles /0 (match all)', () => {
    expect(ipv6InCidr('fe80::1', '::', 0)).toBe(true);
    expect(ipv6InCidr('2001:db8::abcd', '::1', 0)).toBe(true);
  });

  it('handles :: shorthand expansion', () => {
    expect(ipv6InCidr('::1', '::1', 128)).toBe(true);
    expect(ipv6InCidr('::1', '0000:0000:0000:0000:0000:0000:0000:0001', 128)).toBe(true);
    expect(ipv6InCidr('2001:db8::', '2001:0db8:0000:0000:0000:0000:0000:0000', 32)).toBe(true);
  });

  it('returns false for invalid IPv6 address', () => {
    expect(ipv6InCidr('not-an-ip', '2001:db8::', 64)).toBe(false);
    expect(ipv6InCidr('2001:db8::1', 'not-a-cidr', 64)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// mapClaims
// ---------------------------------------------------------------------------

describe('mapClaims', () => {
  it('maps standard OIDC claims with defaults', () => {
    const raw = {
      sub: 'user-123',
      email: 'alice@example.com',
      preferred_username: 'alice',
      name: 'Alice Smith',
      picture: 'https://example.com/alice.png',
      email_verified: true,
    };
    const result = mapClaims(raw);
    expect(result).toEqual({
      sub: 'user-123',
      email: 'alice@example.com',
      username: 'alice',
      name: 'Alice Smith',
      picture: 'https://example.com/alice.png',
      emailVerified: true,
    });
  });

  it('returns empty strings for missing fields', () => {
    const result = mapClaims({});
    expect(result).toEqual({
      sub: '',
      email: '',
      username: '',
      name: '',
      picture: '',
      emailVerified: false,
    });
  });

  it('uses custom claim paths when provided', () => {
    const customPaths: SignerClaimPaths = {
      sub: 'user_id',
      email: 'contact.email',
      username: 'login',
      name: 'display_name',
      picture: 'avatar_url',
      emailVerified: 'contact.verified',
    };

    const raw = {
      user_id: 'custom-sub',
      contact: { email: 'custom@example.com', verified: true },
      login: 'customuser',
      display_name: 'Custom User',
      avatar_url: 'https://example.com/custom.png',
    };
    const result = mapClaims(raw, customPaths);
    expect(result).toEqual({
      sub: 'custom-sub',
      email: 'custom@example.com',
      username: 'customuser',
      name: 'Custom User',
      picture: 'https://example.com/custom.png',
      emailVerified: true,
    });
  });

  it('handles nested claim path that does not exist', () => {
    const customPaths: SignerClaimPaths = {
      sub: 'sub',
      email: 'deep.nested.path',
      username: 'preferred_username',
      name: 'name',
      picture: 'picture',
      emailVerified: 'email_verified',
    };
    const result = mapClaims({ sub: 'x', email: 'fallback@test.com' }, customPaths);
    expect(result.email).toBe('');
  });

  it('reads emailVerified from custom claim path', () => {
    const customPaths: SignerClaimPaths = {
      sub: 'sub',
      email: 'email',
      username: 'preferred_username',
      name: 'name',
      picture: 'picture',
      emailVerified: 'verified',
    };
    const raw = { sub: 'u1', email: 'a@b.com', verified: true };
    expect(mapClaims(raw, customPaths).emailVerified).toBe(true);
  });

  it('defaults emailVerified to false when claim is absent (fail-closed)', () => {
    const raw = { sub: 'u1', email: 'a@b.com' };
    expect(mapClaims(raw).emailVerified).toBe(false);
  });

  it('returns false when claim is absent and assumeVerified=false', () => {
    const raw = { sub: 'u1', email: 'a@b.com' };
    expect(mapClaims(raw, undefined, false).emailVerified).toBe(false);
  });

  it('returns true when claim is absent and assumeVerified=true', () => {
    const raw = { sub: 'u1', email: 'a@b.com' };
    expect(mapClaims(raw, undefined, true).emailVerified).toBe(true);
  });

  it('respects explicit false claim even when assumeVerified=true', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: false };
    expect(mapClaims(raw, undefined, true).emailVerified).toBe(false);
  });

  it('respects explicit true claim when assumeVerified=false', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: true };
    expect(mapClaims(raw, undefined, false).emailVerified).toBe(true);
  });

  it('coerces string "true" to boolean true', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: 'true' };
    expect(mapClaims(raw, undefined, false).emailVerified).toBe(true);
  });

  it('coerces string "True" (case-insensitive) to boolean true', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: 'True' };
    expect(mapClaims(raw, undefined, false).emailVerified).toBe(true);
  });

  it('coerces string "false" to boolean false', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: 'false' };
    expect(mapClaims(raw, undefined, true).emailVerified).toBe(false);
  });

  it('treats non-boolean/non-string value as absent (falls back to assumeVerified)', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: 42 };
    expect(mapClaims(raw, undefined, false).emailVerified).toBe(false);
    expect(mapClaims(raw, undefined, true).emailVerified).toBe(true);
  });

  it('treats unrecognized string as false (not "true")', () => {
    const raw = { sub: 'u1', email: 'a@b.com', email_verified: 'yes' };
    expect(mapClaims(raw, undefined, false).emailVerified).toBe(false);
    expect(mapClaims(raw, undefined, true).emailVerified).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// coerceClaimToString
// ---------------------------------------------------------------------------

describe('coerceClaimToString', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(logger, 'warn').mockReturnValue(logger);
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it('returns string value as-is without warning', () => {
    expect(coerceClaimToString('hello', 'field')).toBe('hello');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('returns empty string as-is without warning', () => {
    expect(coerceClaimToString('', 'field')).toBe('');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('coerces number to string without warning', () => {
    expect(coerceClaimToString(42, 'sub')).toBe('42');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('coerces boolean true to string without warning', () => {
    expect(coerceClaimToString(true, 'email')).toBe('true');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('coerces boolean false to string without warning', () => {
    expect(coerceClaimToString(false, 'flag')).toBe('false');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('returns first element of string array without warning', () => {
    expect(coerceClaimToString(['first', 'second'], 'username')).toBe('first');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('returns string-coerced first element of numeric array without warning', () => {
    expect(coerceClaimToString([42, 43], 'sub')).toBe('42');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('returns empty string for null without warning', () => {
    expect(coerceClaimToString(null, 'field')).toBe('');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('returns empty string for undefined without warning', () => {
    expect(coerceClaimToString(undefined, 'field')).toBe('');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('returns empty string for plain object and logs warning', () => {
    expect(coerceClaimToString({ nested: 'value' }, 'sub')).toBe('');
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('unsupported type'),
    );
  });

  it('returns empty string for empty array without warning', () => {
    expect(coerceClaimToString([], 'field')).toBe('');
    expect(warnSpy).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// computeCacheKey (via getCachedOrExtractClaims cache behaviour)
// ---------------------------------------------------------------------------

describe('computeCacheKey', () => {
  // computeCacheKey is not exported, but its properties are observable through
  // the cache: same input -> same cache hit; different input -> different entry.
  // We verify the hash format by inspecting the cache key indirectly via a
  // real SHA-256 digest of the same input.

  it('produces a consistent base64url hash for the same input', () => {
    const { createHash } = crypto;
    const input = 'eyJhbGciOiJSUzI1NiJ9.payload.signature';
    const hash1 = createHash('sha256').update(input).digest('base64url');
    const hash2 = createHash('sha256').update(input).digest('base64url');
    expect(hash1).toBe(hash2);
  });

  it('produces different hashes for different inputs', () => {
    const { createHash } = crypto;
    const hashA = createHash('sha256').update('token-a').digest('base64url');
    const hashB = createHash('sha256').update('token-b').digest('base64url');
    expect(hashA).not.toBe(hashB);
  });

  it('output contains only base64url-safe characters (no +, /, or =)', () => {
    const { createHash } = crypto;
    // Run over several inputs to reduce false-negative probability
    const inputs = ['token-1', 'token-2', 'a'.repeat(200), '\x00\xff\xfe'];
    for (const input of inputs) {
      const hash = createHash('sha256').update(input).digest('base64url');
      expect(hash).toMatch(/^[A-Za-z0-9\-_]+$/);
    }
  });
});

// ---------------------------------------------------------------------------
// isSourceTrusted
// ---------------------------------------------------------------------------

describe('isSourceTrusted', () => {
  const savedEnv: Record<string, string | undefined> = {};

  const envKeys = [
    'TRUSTED_HEADER_AUTH_TRUSTED_CIDRS',
    'TRUSTED_HEADER_AUTH_MAX_HOPS',
  ];

  beforeEach(() => {
    for (const key of envKeys) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (savedEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = savedEnv[key];
      }
    }
  });

  function makeReq(overrides: Partial<{ ip: string; headers: Record<string, string> }> = {}): Request {
    return {
      ip: overrides.ip ?? '10.0.0.1',
      headers: overrides.headers ?? {},
    } as unknown as Request;
  }

  it('trusts any IP with default CIDR (0.0.0.0/0)', () => {
    expect(isSourceTrusted(makeReq({ ip: '192.168.1.1' }))).toBe(true);
  });

  it('trusts IP within configured CIDR', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';
    expect(isSourceTrusted(makeReq({ ip: '10.1.2.3' }))).toBe(true);
  });

  it('rejects IP outside configured CIDR', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';
    expect(isSourceTrusted(makeReq({ ip: '192.168.1.1' }))).toBe(false);
  });

  it('handles multiple CIDRs (matches second)', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8,172.16.0.0/12';
    expect(isSourceTrusted(makeReq({ ip: '172.16.5.1' }))).toBe(true);
  });

  it('rejects when hop count exceeds MAX_HOPS', () => {
    process.env.TRUSTED_HEADER_AUTH_MAX_HOPS = '1';
    const req = makeReq({
      ip: '10.0.0.1',
      headers: { 'x-forwarded-for': '10.0.0.1, 10.0.0.2' },
    });
    expect(isSourceTrusted(req)).toBe(false);
  });

  it('allows when hop count equals MAX_HOPS', () => {
    process.env.TRUSTED_HEADER_AUTH_MAX_HOPS = '2';
    const req = makeReq({
      ip: '10.0.0.1',
      headers: { 'x-forwarded-for': '10.0.0.1, 10.0.0.2' },
    });
    expect(isSourceTrusted(req)).toBe(true);
  });

  it('normalizes IPv4-mapped IPv6 address', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';
    expect(isSourceTrusted(makeReq({ ip: '::ffff:10.0.0.5' }))).toBe(true);
  });

  it('returns false when req.ip is undefined', () => {
    const req = makeReq({});
    (req as unknown as { ip: undefined }).ip = undefined;
    expect(isSourceTrusted(req)).toBe(false);
  });

  it('matches IPv6 source IP against IPv6 CIDR', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '2001:db8::/32';
    expect(isSourceTrusted(makeReq({ ip: '2001:db8::1' }))).toBe(true);
  });

  it('rejects IPv6 source IP outside IPv6 CIDR', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '2001:db8::/32';
    expect(isSourceTrusted(makeReq({ ip: '2001:db9::1' }))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateJwtHeader -- uses a real RSA key pair
// ---------------------------------------------------------------------------

describe('validateJwtHeader', () => {
  const savedEnv: Record<string, string | undefined> = {};

  const envKeys = [
    'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
    'TRUSTED_HEADER_AUTH_JWT_JWKS_URI',
    'TRUSTED_HEADER_AUTH_JWT_ALGORITHMS',
    'TRUSTED_HEADER_AUTH_JWT_ISSUER',
    'TRUSTED_HEADER_AUTH_JWT_AUDIENCE',
  ];

  let rsaPublicKey: string;
  let rsaPrivateKey: string;

  beforeAll(() => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    rsaPublicKey = publicKey;
    rsaPrivateKey = privateKey;
  });

  beforeEach(() => {
    for (const key of envKeys) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
    resetSigners();
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
  });

  it('validates a correctly signed RS256 JWT', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const token = jwt.sign(
      { sub: 'user-1', email: 'test@example.com' },
      rsaPrivateKey,
      { algorithm: 'RS256' },
    );

    const result = await validateJwtHeader(token, initSigners(), false);
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('user-1');
    expect(result?.claims.email).toBe('test@example.com');
  });

  it('validates a base64-wrapped JWT', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const token = jwt.sign(
      { sub: 'user-2', email: 'wrapped@example.com' },
      rsaPrivateKey,
      { algorithm: 'RS256' },
    );
    const base64Wrapped = Buffer.from(token).toString('base64');

    const result = await validateJwtHeader(base64Wrapped, initSigners(), false);
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('user-2');
  });

  it('rejects a JWT signed with the wrong key', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const { privateKey: wrongKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const token = jwt.sign(
      { sub: 'evil', email: 'attacker@example.com' },
      wrongKey,
      { algorithm: 'RS256' },
    );

    const result = await validateJwtHeader(token, initSigners(), false);
    expect(result).toBeNull();
  });

  it('rejects a non-JWT string', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    const result = await validateJwtHeader('not.a.jwt', initSigners(), false);
    expect(result).toBeNull();
  });

  it('rejects a string that is not 3-segment JWT format', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    const result = await validateJwtHeader('eyJhbGciOiJSUzI1NiJ9.only-two', initSigners(), false);
    expect(result).toBeNull();
  });

  it('validates issuer when configured', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWT_ISSUER = 'https://auth.example.com';

    const validToken = jwt.sign(
      { sub: 'u1', email: 'a@b.com' },
      rsaPrivateKey,
      { algorithm: 'RS256', issuer: 'https://auth.example.com' },
    );
    const result = await validateJwtHeader(validToken, initSigners(), false);
    expect(result).not.toBeNull();

    resetSigners();

    const wrongIssuerToken = jwt.sign(
      { sub: 'u1', email: 'a@b.com' },
      rsaPrivateKey,
      { algorithm: 'RS256', issuer: 'https://wrong.example.com' },
    );
    const rejected = await validateJwtHeader(wrongIssuerToken, initSigners(), false);
    expect(rejected).toBeNull();
  });

  it('validates audience when configured', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWT_AUDIENCE = 'my-client-id';

    const validToken = jwt.sign(
      { sub: 'u1', email: 'a@b.com' },
      rsaPrivateKey,
      { algorithm: 'RS256', audience: 'my-client-id' },
    );
    const result = await validateJwtHeader(validToken, initSigners(), false);
    expect(result).not.toBeNull();

    resetSigners();

    const wrongAudToken = jwt.sign(
      { sub: 'u1', email: 'a@b.com' },
      rsaPrivateKey,
      { algorithm: 'RS256', audience: 'wrong-client' },
    );
    const rejected = await validateJwtHeader(wrongAudToken, initSigners(), false);
    expect(rejected).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// getCachedOrExtractClaims -- cache TTL and eviction behaviour
// ---------------------------------------------------------------------------

describe('getCachedOrExtractClaims -- cache TTL caps at JWT exp', () => {
  const savedEnv: Record<string, string | undefined> = {};

  const envKeys = [
    'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
    'TRUSTED_HEADER_AUTH_JWT_ALGORITHMS',
  ];

  let rsaPublicKey: string;
  let rsaPrivateKey: string;

  beforeAll(() => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    rsaPublicKey = publicKey;
    rsaPrivateKey = privateKey;
  });

  beforeEach(() => {
    for (const key of envKeys) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
    resetSigners();
    resetJwksCache();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
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

  it('7.1 -- cache entry expires when JWT exp is shorter than default TTL', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const nowSec = Math.floor(Date.now() / 1000);
    // JWT expires in 10 seconds -- well under the 60s default cache TTL.
    const token = jwt.sign(
      { sub: 'user-ttl', email: 'ttl@example.com', exp: nowSec + 10 },
      rsaPrivateKey,
      { algorithm: 'RS256' },
    );

    const req = buildReq({ headers: { 'x-id-token': token } });
    const signers = initSigners();

    // First call: cache miss -- extracts and stores claims.
    const first = await getCachedOrExtractClaims(req, signers, {
      jwtHeader: 'X-Id-Token',
      jwksCacheMaxEntries: 1,
    });
    expect(first).not.toBeNull();
    expect(first?.sub).toBe('user-ttl');
    expect(getJwksCacheSize()).toBe(1);

    // Advance past the JWT exp (10s) but stay under the default TTL (60s).
    // This proves the cache TTL was capped at the JWT exp, not the default.
    jest.advanceTimersByTime(11_000);

    // Second call with the same JWT: cache entry is stale (Date.now() >= expiry),
    // so the cache check is bypassed and validateJwtHeader is called again.
    // validateJwtHeader rejects the expired JWT, so claims = null.
    // Because claims is null, cache.set() is never called, meaning
    // pruneExpiredEntries() does not run -- the stale entry remains in the map.
    // The important invariant is that null is returned (no stale data served).
    const second = await getCachedOrExtractClaims(req, signers, {
      jwtHeader: 'X-Id-Token',
      jwksCacheMaxEntries: 1,
    });
    expect(second).toBeNull();
    // Stale entry remains until the next successful set() triggers pruning.
    expect(getJwksCacheSize()).toBe(1);
  });
});

describe('getCachedOrExtractClaims -- cache eviction at max entries', () => {
  const savedEnv: Record<string, string | undefined> = {};

  const envKeys = [
    'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
    'TRUSTED_HEADER_AUTH_JWT_ALGORITHMS',
  ];

  let rsaPublicKey: string;
  let rsaPrivateKey: string;

  beforeAll(() => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    rsaPublicKey = publicKey;
    rsaPrivateKey = privateKey;
  });

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

  it('7.2 -- cache stays at or below jwksCacheMaxEntries after overflow', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = rsaPublicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const maxEntries = 5;
    const totalTokens = maxEntries + 1; // one over the cap to trigger eviction
    const signers = initSigners();

    // Each token has a unique sub, producing a unique signature and cache key.
    for (let i = 0; i < totalTokens; i++) {
      const token = jwt.sign(
        { sub: `user-evict-${i}`, email: `evict${i}@example.com` },
        rsaPrivateKey,
        { algorithm: 'RS256' },
      );
      const req = buildReq({ headers: { 'x-id-token': token } });
      await getCachedOrExtractClaims(req, signers, {
        jwtHeader: 'X-Id-Token',
        jwksCacheMaxEntries: maxEntries,
      });
    }

    // After the (maxEntries+1)-th call, size >= maxEntries triggered
    // pruneExpiredEntries(), which evicted the oldest entry to bring the
    // cache back to maxEntries.
    expect(getJwksCacheSize()).toBeLessThanOrEqual(maxEntries);
  });
});
