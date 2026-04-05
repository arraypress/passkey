export interface PasskeyConfig {
  rpName: string;
  rpId: string;
  origin: string;
}

export interface PasskeyUser {
  id: string;
  name: string;
  displayName?: string;
}

export interface RegistrationResponse {
  clientDataJSON: string;
  attestationObject: string;
}

export interface AuthenticationResponse {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}

export interface StoredCredential {
  publicKey: Uint8Array;
  counter: number;
}

export interface VerifiedRegistration {
  credentialId: string;
  publicKey: Uint8Array;
  counter: number;
}

export interface VerifiedAuthentication {
  credentialId: string;
  newCounter: number;
}

/** Generate a random 32-byte base64url challenge. */
export function generateChallenge(): string;

/** Generate registration options for navigator.credentials.create(). */
export function generateRegistrationOptions(
  config: Pick<PasskeyConfig, 'rpName' | 'rpId'>,
  user: PasskeyUser,
  excludeCredentials?: string[]
): { challenge: string; options: Record<string, unknown> };

/** Verify a registration response from the browser. */
export function verifyRegistration(
  config: Pick<PasskeyConfig, 'rpId' | 'origin'>,
  response: RegistrationResponse,
  storedChallenge: string
): VerifiedRegistration;

/** Generate authentication options for navigator.credentials.get(). */
export function generateAuthenticationOptions(
  config: Pick<PasskeyConfig, 'rpId'>,
  allowCredentials?: string[]
): { challenge: string; options: Record<string, unknown> };

/** Verify an authentication response from the browser. */
export function verifyAuthentication(
  config: Pick<PasskeyConfig, 'rpId' | 'origin'>,
  response: AuthenticationResponse,
  storedCredential: StoredCredential,
  storedChallenge: string
): VerifiedAuthentication;

/** Get passkey config from a URL. */
export function getConfig(url: string | URL, siteName?: string): PasskeyConfig;

/** Check if a challenge has expired. */
export function isChallengeExpired(createdAt: string, ttlMs?: number): boolean;

/** Max passkeys per user (10). */
export declare const MAX_PASSKEYS_PER_USER: number;

/** Challenge TTL in ms (300000 = 5 minutes). */
export declare const CHALLENGE_TTL: number;
