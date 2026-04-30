import type {
  RegistrationResponse,
  AuthenticationResponse,
  VerifiedRegistration,
  VerifiedAuthentication,
  PasskeyConfig,
  PasskeyUser,
} from './index.d.ts';

export type ChallengeType = 'registration' | 'authentication' | string;

/** Stored challenge row shape — either camelCase or snake_case `userId` accepted. Null allowed for nullable columns. */
export interface StoredChallenge {
  type: string;
  userId?: string | number | null;
  user_id?: string | number | null;
  data?: string | null;
}

/** Stored credential row shape — either camelCase or snake_case `publicKey` accepted. */
export interface StoredCredentialRow {
  id?: string;
  publicKey?: string | Uint8Array | null;
  public_key?: string | Uint8Array | null;
  counter?: number | null;
}

export interface StoreChallengeInput<TUserId = string | number> {
  challenge: string;
  type: ChallengeType;
  userId?: TUserId;
  data?: string;
  expiresAt: string;
}

export class PasskeyFlowError extends Error {
  readonly name: 'PasskeyFlowError';
  readonly code: 'invalid_challenge' | 'credential_not_found' | 'verification_failed';
  constructor(code: PasskeyFlowError['code'], message: string);
}

/** Encode a Uint8Array as base64url for DB persistence. */
export function encodeBase64Url(buf: Uint8Array): string;

/** Decode a base64url string back to Uint8Array. */
export function decodeBase64Url(str: string): Uint8Array;

/**
 * Derive a PasskeyConfig from the request's Origin header.
 * Prefers the header; falls back to the request URL when missing.
 */
export function getConfigFromOrigin(
  originHeader: string | null | undefined,
  fallbackUrl: string | URL,
  rpName?: string,
): PasskeyConfig;

/** ISO-8601 timestamp for a challenge TTL (default 5 minutes). */
export function challengeExpiry(ttlMs?: number): string;

export interface InitRegistrationOptions<TUserId = string | number> {
  config: Pick<PasskeyConfig, 'rpName' | 'rpId'>;
  user: PasskeyUser;
  exclude?: string[];
  storeChallenge: (row: StoreChallengeInput<TUserId>) => Promise<unknown>;
  type?: ChallengeType;
  userId?: TUserId;
  data?: string;
  ttlMs?: number;
}

/** Generate registration options + persist the challenge. Step 1 of a ceremony. */
export function initRegistration<TUserId = string | number>(
  opts: InitRegistrationOptions<TUserId>,
): Promise<{ challenge: string; options: Record<string, unknown> }>;

export interface RunRegistrationCeremonyOptions<TStored extends StoredChallenge = StoredChallenge> {
  config: Pick<PasskeyConfig, 'rpId' | 'origin'>;
  response: RegistrationResponse;
  challengeStr: string;
  getChallenge: (challenge: string) => Promise<TStored | null | undefined>;
  deleteChallenge: (challenge: string) => Promise<unknown>;
  expectedType?: ChallengeType;
  expectedUserId?: string | number;
}

export interface RegistrationCeremonyResult extends VerifiedRegistration {
  publicKeyBase64: string;
  data: string | undefined;
}

/** Fetch challenge → verify registration → delete challenge. Throws PasskeyFlowError. */
export function runRegistrationCeremony<TStored extends StoredChallenge = StoredChallenge>(
  opts: RunRegistrationCeremonyOptions<TStored>,
): Promise<RegistrationCeremonyResult>;

export interface InitAuthenticationOptions<TUserId = string | number> {
  config: Pick<PasskeyConfig, 'rpId'>;
  allowCredentials?: string[];
  storeChallenge: (row: StoreChallengeInput<TUserId>) => Promise<unknown>;
  userId?: TUserId;
  ttlMs?: number;
}

/** Generate authentication options + persist the challenge. Step 1 of a login. */
export function initAuthentication<TUserId = string | number>(
  opts: InitAuthenticationOptions<TUserId>,
): Promise<{ challenge: string; options: Record<string, unknown> }>;

export interface RunAuthenticationCeremonyOptions<TCredential extends StoredCredentialRow = StoredCredentialRow> {
  config: Pick<PasskeyConfig, 'rpId' | 'origin'>;
  response: AuthenticationResponse;
  challengeStr: string;
  getChallenge: (challenge: string) => Promise<{ type: string } | null | undefined>;
  deleteChallenge: (challenge: string) => Promise<unknown>;
  getCredentialById: (credentialId: string) => Promise<TCredential | null | undefined>;
  updateCounter?: (credentialId: string, newCounter: number) => Promise<unknown>;
  expectedType?: ChallengeType;
  /** Use verifyAuthenticationAsync (supports Ed25519). Default true. */
  async?: boolean;
}

export interface AuthenticationCeremonyResult<TCredential extends StoredCredentialRow = StoredCredentialRow>
  extends VerifiedAuthentication {
  credential: TCredential;
}

/** Fetch challenge → lookup credential → verify → delete challenge → bump counter. */
export function runAuthenticationCeremony<TCredential extends StoredCredentialRow = StoredCredentialRow>(
  opts: RunAuthenticationCeremonyOptions<TCredential>,
): Promise<AuthenticationCeremonyResult<TCredential>>;
