import crypto from 'crypto';
import { logger } from '@librechat/data-schemas';
import { initSigners, resetSigners } from './signers';
import { logConfig } from './logConfig';

// Env vars that logConfig reads (via env() helper and initSigners)
const envKeys = [
  'TRUSTED_HEADER_AUTH_ENABLED',
  'TRUSTED_HEADER_AUTH_TRUST_UNSIGNED',
  'TRUSTED_HEADER_AUTH_TRUSTED_CIDRS',
  'TRUSTED_HEADER_AUTH_JWT_HEADER',
  'TRUSTED_HEADER_AUTH_USERINFO_HEADER',
  'TRUSTED_HEADER_AUTH_EMAIL_HEADER',
  'TRUSTED_HEADER_AUTH_MAX_HOPS',
  'TRUSTED_HEADER_AUTH_ALLOW_DOMAINS',
  'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWT_JWKS_URI',
  'TRUSTED_HEADER_AUTH_JWT_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWT_ISSUER',
  'TRUSTED_HEADER_AUTH_JWT_AUDIENCE',
  'TRUSTED_HEADER_AUTH_ASSUME_EMAIL_VERIFIED',
  'TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWKS_0_URI',
  'TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWKS_0_ISSUER',
  'TRUSTED_HEADER_AUTH_JWKS_0_AUDIENCE',
  'TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWKS_1_URI',
  'TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWKS_1_ISSUER',
  'TRUSTED_HEADER_AUTH_JWKS_1_AUDIENCE',
  'TRUSTED_HEADER_AUTH_JWKS_GLOBAL_CLAIMS_FALLBACK',
];

const savedEnv: Record<string, string | undefined> = {};

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

describe('logConfig()', () => {
  let infoSpy: jest.SpyInstance;
  let warnSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;

  beforeEach(() => {
    infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => logger);
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => logger);
  });

  afterEach(() => {
    infoSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it('logs signer info when a JWT public key is configured', () => {
    const { publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = publicKey;

    logConfig(initSigners());

    const infoCalls = infoSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(infoCalls).toEqual(
      expect.arrayContaining([
        expect.stringContaining('=== Configuration ==='),
        expect.stringContaining('Static PEM key'),
      ]),
    );
    expect(errorSpy).not.toHaveBeenCalledWith(
      expect.stringContaining('No JWT signers configured'),
    );
  });

  it('logs unsigned+CIDR configuration when TRUST_UNSIGNED=true and CIDR is strict', () => {
    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUSTED_CIDRS = '10.0.0.0/8';

    logConfig(initSigners());

    const warnCalls = warnSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(warnCalls).toEqual(
      expect.arrayContaining([
        expect.stringContaining('Unsigned headers are trusted'),
      ]),
    );
    expect(errorSpy).not.toHaveBeenCalledWith(
      expect.stringContaining('MISCONFIGURATION'),
    );
  });

  it('logs a warning about misconfiguration when no signers and no unsigned trust', () => {
    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';

    logConfig(initSigners());

    const errorCalls = errorSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(errorCalls).toEqual(
      expect.arrayContaining([
        expect.stringContaining('No JWT signers configured'),
      ]),
    );
  });

  it('logs multi-signer details when multiple signers are active', () => {
    const keyA = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const keyB = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://idp-a.example.com';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ISSUER = 'https://idp-b.example.com';

    logConfig(initSigners());

    const infoCalls = infoSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(infoCalls).toEqual(
      expect.arrayContaining([
        expect.stringContaining('Multi-signer mode: 2 signers configured'),
        expect.stringContaining('Signer 0: Static PEM key'),
        expect.stringContaining('Signer 1: Static PEM key'),
      ]),
    );
  });

  it('does not log anything when ENABLED is false', () => {
    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'false';

    logConfig(initSigners());

    expect(infoSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('logs MISCONFIGURATION error when TRUST_UNSIGNED=true but CIDR is not strict', () => {
    process.env.TRUSTED_HEADER_AUTH_ENABLED = 'true';
    process.env.TRUSTED_HEADER_AUTH_TRUST_UNSIGNED = 'true';
    // No TRUSTED_CIDRS set -- defaults to 0.0.0.0/0 (not strict)

    logConfig(initSigners());

    const errorCalls = errorSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(errorCalls).toEqual(
      expect.arrayContaining([
        expect.stringContaining('MISCONFIGURATION'),
      ]),
    );
  });
});
