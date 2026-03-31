/**
 * Tests for multi-signer JWKS support: initSigners, iss-based routing,
 * sequential fallback, per-signer claim paths, and startup validation.
 */
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { initSigners, resetSigners } from './signers';
import { validateJwtHeader } from './jwt';
import { mapClaims } from './claims';

// Two RSA key pairs to simulate two independent IdP signers
let keyA: { publicKey: string; privateKey: string };
let keyB: { publicKey: string; privateKey: string };

beforeAll(() => {
  keyA = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  keyB = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
});

// Comprehensive list of env vars that multi-signer tests may set
const envKeys = [
  'TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWT_JWKS_URI',
  'TRUSTED_HEADER_AUTH_JWT_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWT_ISSUER',
  'TRUSTED_HEADER_AUTH_JWT_AUDIENCE',
  'TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWKS_0_ISSUER',
  'TRUSTED_HEADER_AUTH_JWKS_0_AUDIENCE',
  'TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWKS_0_SUB_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_0_EMAIL_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_0_USERNAME_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_0_NAME_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_0_PICTURE_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWKS_1_ISSUER',
  'TRUSTED_HEADER_AUTH_JWKS_1_AUDIENCE',
  'TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWKS_1_SUB_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_1_EMAIL_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_1_USERNAME_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_1_NAME_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_1_PICTURE_CLAIM',
  'TRUSTED_HEADER_AUTH_JWKS_2_PUBLIC_KEY',
  'TRUSTED_HEADER_AUTH_JWKS_2_ALGORITHMS',
  'TRUSTED_HEADER_AUTH_JWKS_GLOBAL_CLAIMS_FALLBACK',
  'TRUSTED_HEADER_AUTH_USERINFO_SUB_CLAIM',
  'TRUSTED_HEADER_AUTH_USERINFO_EMAIL_CLAIM',
  'TRUSTED_HEADER_AUTH_USERINFO_USERNAME_CLAIM',
  'TRUSTED_HEADER_AUTH_USERINFO_NAME_CLAIM',
  'TRUSTED_HEADER_AUTH_USERINFO_PICTURE_CLAIM',
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

function signToken(
  payload: Record<string, unknown>,
  privateKey: string,
  opts: jwt.SignOptions = {},
): string {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', ...opts });
}

function setupTwoSigners(): void {
  process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
  process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
  process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://idp-a.example.com';
  process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
  process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';
  process.env.TRUSTED_HEADER_AUTH_JWKS_1_ISSUER = 'https://idp-b.example.com';
}

// ---------------------------------------------------------------------------
// initSigners
// ---------------------------------------------------------------------------

describe('initSigners', () => {
  it('creates two signers from indexed env vars', () => {
    setupTwoSigners();
    const result = initSigners();
    expect(result).toHaveLength(2);
    expect(result[0].issuer).toBe('https://idp-a.example.com');
    expect(result[1].issuer).toBe('https://idp-b.example.com');
    expect(result[0].index).toBe(0);
    expect(result[1].index).toBe(1);
  });

  it('falls back to legacy vars when no indexed vars exist', () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWT_ISSUER = 'https://legacy.example.com';
    const result = initSigners();
    expect(result).toHaveLength(1);
    expect(result[0].issuer).toBe('https://legacy.example.com');
  });

  it('returns empty array when no JWT config is present', () => {
    const result = initSigners();
    expect(result).toHaveLength(0);
  });

  it('returns cached signers on second call', () => {
    setupTwoSigners();
    const first = initSigners();
    const second = initSigners();
    expect(first).toBe(second);
  });

  it('skips gaps in indexed vars and discovers signers on both sides', () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    // Skip slot 1 -- slot 2 should still be discovered
    process.env.TRUSTED_HEADER_AUTH_JWKS_2_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_2_ALGORITHMS = 'RS256';
    const result = initSigners();
    expect(result).toHaveLength(2);
  });

  it('assigns JWKS client as null for PEM-based signers', () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    const result = initSigners();
    expect(result[0].client).toBeNull();
    expect(result[0].publicKey).toBe(keyA.publicKey);
  });
});

// ---------------------------------------------------------------------------
// validateJwtHeader -- issuer-based routing
// ---------------------------------------------------------------------------

describe('validateJwtHeader -- multi-signer iss routing', () => {
  it('routes JWT to signer matching its iss claim', async () => {
    setupTwoSigners();
    const token = signToken(
      { sub: 'user-a', email: 'a@example.com', iss: 'https://idp-a.example.com' },
      keyA.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('user-a');
    expect(result?.signer.index).toBe(0);
  });

  it('routes JWT to second signer when iss matches slot 1', async () => {
    setupTwoSigners();
    const token = signToken(
      { sub: 'user-b', email: 'b@example.com', iss: 'https://idp-b.example.com' },
      keyB.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('user-b');
    expect(result?.signer.index).toBe(1);
  });

  it('rejects JWT when iss matches signer but key is wrong (fail-closed)', async () => {
    setupTwoSigners();
    // Sign with key B but use signer A's issuer
    const token = signToken(
      { sub: 'evil', email: 'evil@example.com', iss: 'https://idp-a.example.com' },
      keyB.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).toBeNull();
  });

  it('rejects JWT when no signer issuer matches', async () => {
    setupTwoSigners();
    const token = signToken(
      { sub: 'unknown', email: 'unknown@example.com', iss: 'https://unknown-idp.example.com' },
      keyA.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).toBeNull();
  });

  it('rejects JWT with no iss when multiple signers configured', async () => {
    setupTwoSigners();
    const token = signToken(
      { sub: 'no-iss', email: 'noiss@example.com' },
      keyA.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// validateJwtHeader -- multi-issuer-match (key rotation support)
// ---------------------------------------------------------------------------

describe('validateJwtHeader -- multi-issuer-match', () => {
  it('tries second signer when two signers share the same issuer and first key fails', async () => {
    // Simulates key rotation: two signers for the same issuer with different keys
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://shared-idp.example.com';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ISSUER = 'https://shared-idp.example.com';

    // Token signed by key B -- first signer fails, second succeeds
    const token = signToken(
      { sub: 'rotated-user', email: 'rotated@example.com', iss: 'https://shared-idp.example.com' },
      keyB.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('rotated-user');
    expect(result?.signer.index).toBe(1);
  });

  it('returns null when all signers with matching issuer fail verification', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://shared-idp.example.com';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ISSUER = 'https://shared-idp.example.com';

    const { privateKey: unknownKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const token = signToken(
      { sub: 'nobody', email: 'nobody@example.com', iss: 'https://shared-idp.example.com' },
      unknownKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Per-signer claim mapping
// ---------------------------------------------------------------------------

describe('per-signer claim mapping', () => {
  it('uses per-signer claim paths when verifying JWT', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://custom-idp.example.com';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_EMAIL_CLAIM = 'mail';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_USERNAME_CLAIM = 'uid';

    const token = signToken(
      {
        sub: 'custom-sub',
        mail: 'custom@example.com',
        uid: 'custom-user',
        iss: 'https://custom-idp.example.com',
      },
      keyA.privateKey,
    );

    const result = await validateJwtHeader(token, initSigners());
    expect(result).not.toBeNull();

    // Use the signer's claim paths to map claims
    const mapped = mapClaims(result!.claims, result!.signer.claims);
    expect(mapped.email).toBe('custom@example.com');
    expect(mapped.username).toBe('custom-user');
    expect(mapped.sub).toBe('custom-sub');
  });

  it('each signer has independent claim paths', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://idp-a.example.com';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_EMAIL_CLAIM = 'emailAddress';

    process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ISSUER = 'https://idp-b.example.com';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_EMAIL_CLAIM = 'mail';

    // Token from signer 0
    const tokenA = signToken(
      { sub: 'a', emailAddress: 'a@corp.com', iss: 'https://idp-a.example.com' },
      keyA.privateKey,
    );
    const resultA = await validateJwtHeader(tokenA, initSigners());
    const mappedA = mapClaims(resultA!.claims, resultA!.signer.claims);
    expect(mappedA.email).toBe('a@corp.com');

    // Reset signers for fresh init with same env
    resetSigners();

    // Token from signer 1
    const tokenB = signToken(
      { sub: 'b', mail: 'b@other.com', iss: 'https://idp-b.example.com' },
      keyB.privateKey,
    );
    const resultB = await validateJwtHeader(tokenB, initSigners());
    const mappedB = mapClaims(resultB!.claims, resultB!.signer.claims);
    expect(mappedB.email).toBe('b@other.com');
  });

  it('falls back to global claim vars when GLOBAL_CLAIMS_FALLBACK is enabled', () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ISSUER = 'https://idp-a.example.com';

    process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ISSUER = 'https://idp-b.example.com';

    // Set global claim fallback and global email claim
    process.env.TRUSTED_HEADER_AUTH_JWKS_GLOBAL_CLAIMS_FALLBACK = 'true';
    process.env.TRUSTED_HEADER_AUTH_USERINFO_EMAIL_CLAIM = 'globalEmail';

    const result = initSigners();
    // Both signers should have inherited the global email claim
    expect(result[0].claims.email).toBe('globalEmail');
    expect(result[1].claims.email).toBe('globalEmail');
  });

  it('per-signer claim takes precedence over global when both are set', () => {
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_ALGORITHMS = 'RS256';
    process.env.TRUSTED_HEADER_AUTH_JWKS_0_EMAIL_CLAIM = 'perSignerEmail';

    process.env.TRUSTED_HEADER_AUTH_JWKS_1_PUBLIC_KEY = keyB.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWKS_1_ALGORITHMS = 'RS256';

    process.env.TRUSTED_HEADER_AUTH_JWKS_GLOBAL_CLAIMS_FALLBACK = 'true';
    process.env.TRUSTED_HEADER_AUTH_USERINFO_EMAIL_CLAIM = 'globalEmail';

    const result = initSigners();
    // Signer 0 has explicit per-signer, should win
    expect(result[0].claims.email).toBe('perSignerEmail');
    // Signer 1 has no per-signer, should fall back to global
    expect(result[1].claims.email).toBe('globalEmail');
  });
});

// ---------------------------------------------------------------------------
// Single-signer with no issuer (backward-compatible)
// ---------------------------------------------------------------------------

describe('single-signer backward compatibility', () => {
  it('verifies JWT with no issuer configured or in token', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const token = signToken(
      { sub: 'single-user', email: 'single@example.com' },
      keyA.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('single-user');
    expect(result?.signer.index).toBe(0);
  });

  it('verifies JWT even when token has iss but signer has no issuer constraint', async () => {
    process.env.TRUSTED_HEADER_AUTH_JWT_PUBLIC_KEY = keyA.publicKey;
    process.env.TRUSTED_HEADER_AUTH_JWT_ALGORITHMS = 'RS256';

    const token = signToken(
      { sub: 'iss-user', email: 'iss@example.com', iss: 'https://any-idp.example.com' },
      keyA.privateKey,
    );
    const result = await validateJwtHeader(token, initSigners());
    expect(result).not.toBeNull();
    expect(result?.claims.sub).toBe('iss-user');
  });
});
