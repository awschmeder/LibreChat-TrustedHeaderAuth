import type { IUser, AppConfig, BalanceConfig } from '@librechat/data-schemas';
import type { RequestHandler } from 'express';
import type { Algorithm } from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';

/** Claim mapping paths for extracting user profile from JWT/userinfo. */
export interface SignerClaimPaths {
  sub: string;
  email: string;
  username: string;
  name: string;
  picture: string;
  emailVerified: string;
}

/** Configuration for a single JWKS signer (parsed from env vars). */
export interface JwksSignerConfig {
  /** JWKS endpoint URL. Mutually exclusive with publicKey. */
  uri?: string;
  /** Static PEM public key. Mutually exclusive with uri. */
  publicKey?: string;
  /** Expected issuer claim. Used for iss-based routing. */
  issuer?: string;
  /** Expected audience claim. */
  audience?: string;
  /** Allowed signing algorithms. */
  algorithms: Algorithm[];
  /** Per-signer claim mapping paths. */
  claims: SignerClaimPaths;
  /** When true, treat absent emailVerified claim as verified. Default: false (fail-closed). */
  assumeVerified: boolean;
}

/** Runtime signer with initialized JWKS client. */
export interface JwksSigner extends JwksSignerConfig {
  /** Lazy-initialized jwks-rsa client (null for static PEM signers). */
  client: JwksClient | null;
  /** Signer index for logging. */
  index: number;
}

export interface HeaderAuthClaims {
  sub: string;
  email: string;
  username: string;
  name: string;
  picture: string;
  emailVerified: boolean;
}

/** Subset of user fields needed for session enforcement. */
export interface UserProviderRecord {
  _id: string;
  email?: string;
  provider: string;
}

/** Decoded refresh token payload. */
export interface RefreshTokenPayload {
  id?: string;
  sessionId?: string;
  exp?: number;
}

/** Query shape for finding a user by openidId or email within a provider. */
export interface FindUserQuery {
  openidId?: string;
  email?: string;
  provider: string;
}

/** Data shape for creating a new header-auth user. */
export interface CreateUserData {
  provider: string;
  openidId: string;
  email: string;
  username: string;
  name: string;
  emailVerified: boolean;
  avatar: string | null;
}

/** Fields that may be updated during profile sync. */
export interface UserProfileUpdates {
  openidId?: string;
  name?: string;
  username?: string;
  email?: string;
  emailVerified?: boolean;
  avatar?: string;
}

/**
 * Injected dependencies for createTrustedHeaderAuthMiddleware.
 * All DB and service calls are passed in so the package has no
 * direct coupling to ~/models or ~/server/services.
 */
export interface HeaderAuthDeps {
  findUser: (query: FindUserQuery) => Promise<IUser | null>;
  createUser: (
    data: CreateUserData,
    balanceConfig: BalanceConfig,
    autoVerify: boolean,
    returnUser: boolean,
  ) => Promise<IUser>;
  updateUser: (id: string, updates: UserProfileUpdates) => Promise<IUser | null>;
  getUserById: (id: string, fields: string) => Promise<UserProviderRecord | null>;
  deleteSession: (query: { sessionId: string }) => Promise<void>;
  /** Issues JWT + refresh token cookies. Throws on failure. */
  setAuthTokens: (userId: string, res: import('express').Response) => Promise<string>;
  getAppConfig: () => Promise<AppConfig>;
  isEnabled: (value: string | undefined) => boolean;
  getBalanceConfig: (appConfig: AppConfig) => BalanceConfig | null;
}

/** Per-request env values frozen at middleware initialization. */
export interface FrozenConfig {
  trustedCidrs: string;
  maxHops: number;
  trustUnsigned: boolean;
  assumeEmailVerified: boolean;
  jwtHeader: string;
  userinfoHeader: string;
  emailHeader: string;
  allowDomains: string;
  /** Pre-parsed domain allowlist; empty Set means wildcard (all domains). */
  parsedAllowDomains: Set<string>;
  jwksCacheMaxEntries: number;
}

/** Decoded but unvalidated claims from an untrusted header. */
export type RawClaims = Record<string, unknown>;

export type TrustedHeaderAuthMiddleware = RequestHandler;

/** Config fields required by extractClaims(). */
export type ClaimsExtractionConfig = Pick<
  FrozenConfig,
  | 'trustUnsigned'
  | 'assumeEmailVerified'
  | 'jwtHeader'
  | 'userinfoHeader'
  | 'emailHeader'
  | 'trustedCidrs'
>;

/** Config fields accepted by getCachedOrExtractClaims() (superset with cache tuning). */
export type CachedClaimsConfig = Partial<
  ClaimsExtractionConfig & Pick<FrozenConfig, 'jwksCacheMaxEntries'>
>;
