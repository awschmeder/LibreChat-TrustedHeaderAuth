import type { Request } from 'express';
import { extractClaims } from './claims';
import { resetJwksCache } from './jwksCache';
import { initSigners, resetSigners } from './signers';
import { readAllConfig, resetCachedConfig } from './env';
import { isCidrStrict } from './network';

// ---------------------------------------------------------------------------
// isCidrStrict
// ---------------------------------------------------------------------------

describe('isCidrStrict', () => {
  const original = process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS;

  afterEach(() => {
    if (original === undefined) {
      delete process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS;
    } else {
      process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = original;
    }
  });

  it('returns false when env var is not set', () => {
    delete process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS;
    expect(isCidrStrict()).toBe(false);
  });

  it('returns false when set to the catch-all 0.0.0.0/0', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '0.0.0.0/0';
    expect(isCidrStrict()).toBe(false);
  });

  it('returns false when set to empty string', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '';
    expect(isCidrStrict()).toBe(false);
  });

  it('returns true for a specific subnet', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';
    expect(isCidrStrict()).toBe(true);
  });

  it('returns false for multiple CIDRs when one is 0.0.0.0/0', () => {
    // A catch-all anywhere in the list means CIDR is not strict
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '0.0.0.0/0,10.0.0.0/8';
    expect(isCidrStrict()).toBe(false);
  });

  it('returns false when ::/0 IPv6 catch-all is present', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8,::/0';
    expect(isCidrStrict()).toBe(false);
  });

  it('returns true for a host /32 address', () => {
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '192.168.1.1/32';
    expect(isCidrStrict()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// extractClaims -- TRUST_UNSIGNED + CIDR guard
// ---------------------------------------------------------------------------

describe('extractClaims -- TRUST_UNSIGNED requires strict CIDR', () => {
  const savedEnv: Record<string, string | undefined> = {};

  const envKeys = [
    'TRUSTED_HEADER_AUTH_TRUST_UNSIGNED',
    'TRUSTED_HEADER_AUTH_TRUSTED_CIDRS',
    'TRUSTED_HEADER_AUTH_JWT_JWKS_URI',
    'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
    'TRUSTED_HEADER_AUTH_USERINFO_HEADER',
    'TRUSTED_HEADER_AUTH_EMAIL_HEADER',
  ];

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

  function makeReq(headers: Record<string, string> = {}): Request {
    return { headers, method: 'GET' } as unknown as Request;
  }

  it('returns null for unsigned userinfo header when CIDR is not strict', async () => {
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    // TRUSTED_CIDRS not set -- defaults to catch-all
    const payload = Buffer.from(JSON.stringify({ sub: 'u1', email: 'u@example.com' })).toString('base64');
    const req = makeReq({ 'x-userinfo': payload });
    const config = readAllConfig();
    const result = await extractClaims(req, initSigners(), config);
    expect(result).toBeNull();
  });

  it('returns null for forwarded email header when CIDR is not strict', async () => {
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    const req = makeReq({ 'x-forwarded-email': 'user@example.com' });
    const config = readAllConfig();
    const result = await extractClaims(req, initSigners(), config);
    expect(result).toBeNull();
  });

  it('returns null for unsigned userinfo header when CIDR is catch-all 0.0.0.0/0', async () => {
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '0.0.0.0/0';
    const payload = Buffer.from(JSON.stringify({ sub: 'u1', email: 'u@example.com' })).toString('base64');
    const req = makeReq({ 'x-userinfo': payload });
    const config = readAllConfig();
    const result = await extractClaims(req, initSigners(), config);
    expect(result).toBeNull();
  });

  it('returns claims for unsigned userinfo header when CIDR is strict', async () => {
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';
    const payload = Buffer.from(
      JSON.stringify({ sub: 'u1', email: 'user@example.com', preferred_username: 'user', name: 'User' }),
    ).toString('base64');
    const req = makeReq({ 'x-userinfo': payload });
    const config = readAllConfig();
    const result = await extractClaims(req, initSigners(), config);
    expect(result).not.toBeNull();
    expect(result?.email).toBe('user@example.com');
  });

  it('returns claims for forwarded email header when CIDR is strict', async () => {
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '172.16.0.0/12';
    const req = makeReq({ 'x-forwarded-email': 'user@example.com' });
    const config = readAllConfig();
    const result = await extractClaims(req, initSigners(), config);
    expect(result).not.toBeNull();
    expect(result?.email).toBe('user@example.com');
  });

  it('returns null when TRUST_UNSIGNED is false and no JWT config', async () => {
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'false';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';
    const payload = Buffer.from(JSON.stringify({ sub: 'u1', email: 'u@example.com' })).toString('base64');
    const req = makeReq({ 'x-userinfo': payload });
    const config = readAllConfig();
    const result = await extractClaims(req, initSigners(), config);
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// readAllConfig -- jwksCacheMaxEntries NaN/negative validation
// ---------------------------------------------------------------------------

describe('readAllConfig -- jwksCacheMaxEntries validation', () => {
  const envKey = 'TRUSTED_HEADER_AUTH_JWKS_CACHE_MAX_ENTRIES';
  let savedValue: string | undefined;

  beforeEach(() => {
    savedValue = process.env[envKey];
    delete process.env[envKey];
  });

  afterEach(() => {
    if (savedValue === undefined) {
      delete process.env[envKey];
    } else {
      process.env[envKey] = savedValue;
    }
  });

  it('defaults to 1000 when env var is not set', () => {
    const config = readAllConfig();
    expect(config.jwksCacheMaxEntries).toBe(1000);
  });

  it('defaults to 1000 when env var is non-numeric (NaN)', () => {
    process.env[envKey] = 'abc';
    const config = readAllConfig();
    expect(config.jwksCacheMaxEntries).toBe(1000);
  });

  it('defaults to 1000 when env var is negative', () => {
    process.env[envKey] = '-5';
    const config = readAllConfig();
    expect(config.jwksCacheMaxEntries).toBe(1000);
  });

  it('uses the configured value when valid and positive', () => {
    process.env[envKey] = '500';
    const config = readAllConfig();
    expect(config.jwksCacheMaxEntries).toBe(500);
  });

  it('uses 0 as a valid value (disables caching)', () => {
    process.env[envKey] = '0';
    const config = readAllConfig();
    expect(config.jwksCacheMaxEntries).toBe(0);
  });
});

