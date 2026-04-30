/**
 * @arraypress/passkey/flow
 *
 * Server-side orchestration helpers for passkey ceremonies.
 *
 * The core `@arraypress/passkey` module is purely stateless — it takes
 * a config + a parsed WebAuthn response + a stored challenge and
 * verifies. Every real app then has to glue that verification to:
 *
 *   1. Pulling the request's Origin header to derive rpId / origin
 *   2. Round-tripping the challenge through some persistence layer
 *   3. Base64url-encoding the returned public key for storage
 *   4. Catching verification errors and turning them into HTTP responses
 *
 * This sub-export wraps all four, so route handlers stop duplicating
 * the same 8-line dance for every ceremony. Storage is pluggable via
 * closures (`storeChallenge` / `getChallenge` / `deleteChallenge` /
 * `getCredentialById`) so the library stays DB-agnostic — pass in
 * functions that call your Kysely / Drizzle / raw-SQL layer.
 *
 * @module @arraypress/passkey/flow
 */

import { encodeBase64urlNoPadding, decodeBase64urlIgnorePadding } from '@oslojs/encoding';
import {
  generateRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  verifyAuthentication,
  verifyAuthenticationAsync,
} from './index.js';

/** Default challenge TTL: 5 minutes. Matches the core module's `CHALLENGE_TTL`. */
const DEFAULT_TTL_MS = 5 * 60 * 1000;

/**
 * Encode a `Uint8Array` as a base64url string.
 *
 * Re-exported from `@oslojs/encoding` so consumers don't need to pull
 * that package in directly for DB persistence of public keys.
 *
 * @param {Uint8Array} buf
 * @returns {string}
 */
export function encodeBase64Url(buf) {
  return encodeBase64urlNoPadding(buf);
}

/**
 * Decode a base64url string back to `Uint8Array`.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function decodeBase64Url(str) {
  return decodeBase64urlIgnorePadding(str);
}

/**
 * Derive a `PasskeyConfig` from the request's `Origin` header.
 *
 * In dev the frontend (e.g. `localhost:5174`) and backend (`localhost:8787`)
 * have different origins. The browser stamps the credential with the
 * frontend's origin, so verification must check the frontend origin —
 * not the request URL's origin. This helper prefers the `Origin` header
 * and falls back to `fallbackUrl` when it's missing (e.g. server-to-server
 * calls where no browser is involved).
 *
 * @param {string|null|undefined} originHeader - Value of the `Origin` request header.
 * @param {string|URL} fallbackUrl - Request URL to fall back on when the header is absent.
 * @param {string} [rpName] - Relying party display name. Defaults to the hostname.
 * @returns {{ rpName: string, rpId: string, origin: string }}
 */
export function getConfigFromOrigin(originHeader, fallbackUrl, rpName) {
  const originStr = originHeader || (
    typeof fallbackUrl === 'string' ? new URL(fallbackUrl).origin : fallbackUrl.origin
  );
  const parsed = new URL(originStr);
  return {
    rpName: rpName || parsed.hostname,
    rpId: parsed.hostname,
    origin: parsed.origin,
  };
}

/**
 * Compute an ISO-formatted expiry timestamp for a WebAuthn challenge.
 *
 * @param {number} [ttlMs] - Time-to-live in ms. Default 5 minutes.
 * @returns {string} ISO-8601 timestamp.
 */
export function challengeExpiry(ttlMs = DEFAULT_TTL_MS) {
  return new Date(Date.now() + ttlMs).toISOString();
}

/**
 * Tagged error thrown by the ceremony runners. The `code` field lets
 * route handlers map each failure to an HTTP status without string
 * matching:
 *
 *   - `invalid_challenge`  — stored challenge missing, type-mismatched,
 *                            or owned by a different user. Map to 400.
 *   - `credential_not_found` — response's credential ID doesn't exist.
 *                              Map to 400 (auth flow) or 404 (detail flow).
 *   - `verification_failed` — cryptographic verification rejected.
 *                             Map to 400.
 */
export class PasskeyFlowError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = 'PasskeyFlowError';
  }
}

/**
 * Step 1 of a registration ceremony — generate options + persist the
 * challenge in one call.
 *
 * Replaces the typical 4-line pattern:
 *   const { challenge, options } = generateRegistrationOptions(...);
 *   await storeChallenge(db, { challenge, type, userId, data, expiresAt });
 *   return c.json({ challenge, options });
 *
 * @template TUserId
 * @param {Object} opts
 * @param {{ rpName: string, rpId: string }} opts.config
 * @param {{ id: string, name: string, displayName?: string }} opts.user
 * @param {string[]} [opts.exclude] - Credential IDs to exclude (existing passkeys).
 * @param {(row: { challenge: string, type: string, userId?: TUserId, data?: string, expiresAt: string }) => Promise<unknown>} opts.storeChallenge
 * @param {string} [opts.type='registration']
 * @param {TUserId} [opts.userId]
 * @param {string} [opts.data] - Arbitrary JSON blob stored with the challenge.
 * @param {number} [opts.ttlMs]
 * @returns {Promise<{ challenge: string, options: Record<string, unknown> }>}
 */
export async function initRegistration({
  config, user, exclude,
  storeChallenge, type = 'registration', userId, data, ttlMs,
}) {
  const { challenge, options } = generateRegistrationOptions(config, user, exclude);
  await storeChallenge({
    challenge,
    type,
    userId,
    data,
    expiresAt: challengeExpiry(ttlMs),
  });
  return { challenge, options };
}

/**
 * Step 2 of a registration ceremony — fetch the stored challenge,
 * verify the browser's attestation, delete the challenge on success.
 *
 * Returns the verified credential plus a base64url-encoded public key
 * (what you want to persist) and the original challenge's `data` blob
 * (for flows like first-run setup that stash the user's email on the
 * challenge before the user row exists).
 *
 * @template TStored
 * @param {Object} opts
 * @param {{ rpId: string, origin: string }} opts.config
 * @param {{ clientDataJSON: string, attestationObject: string }} opts.response
 * @param {string} opts.challengeStr
 * @param {(challenge: string) => Promise<TStored | null | undefined>} opts.getChallenge
 *        Returns `{ type, userId?|user_id?, data? } | null`.
 * @param {(challenge: string) => Promise<unknown>} opts.deleteChallenge
 * @param {string} [opts.expectedType='registration']
 * @param {string|number} [opts.expectedUserId] - If set, the stored challenge's userId must match.
 * @returns {Promise<{ credentialId: string, publicKey: Uint8Array, publicKeyBase64: string, counter: number, keyType: 'ec2'|'ed25519', data: string | undefined }>}
 * @throws {PasskeyFlowError}
 */
export async function runRegistrationCeremony({
  config, response, challengeStr,
  getChallenge, deleteChallenge,
  expectedType = 'registration', expectedUserId,
}) {
  const stored = await getChallenge(challengeStr);
  if (!stored || stored.type !== expectedType) {
    throw new PasskeyFlowError('invalid_challenge', 'Invalid or expired challenge');
  }
  if (expectedUserId !== undefined) {
    const storedUserId = stored.userId ?? stored.user_id;
    if (storedUserId !== expectedUserId) {
      throw new PasskeyFlowError('invalid_challenge', 'Invalid or expired challenge');
    }
  }

  let result;
  try {
    result = verifyRegistration(config, response, challengeStr);
  } catch (err) {
    throw new PasskeyFlowError('verification_failed', `Passkey verification failed: ${err.message}`);
  }

  await deleteChallenge(challengeStr);

  return {
    credentialId: result.credentialId,
    publicKey: result.publicKey,
    publicKeyBase64: encodeBase64urlNoPadding(result.publicKey),
    counter: result.counter,
    keyType: result.keyType,
    data: stored.data,
  };
}

/**
 * Step 1 of an authentication ceremony — generate options + persist
 * the challenge.
 *
 * @template TUserId
 * @param {Object} opts
 * @param {{ rpId: string }} opts.config
 * @param {string[]} [opts.allowCredentials] - Narrow to these credential IDs.
 * @param {(row: { challenge: string, type: string, userId?: TUserId, expiresAt: string }) => Promise<unknown>} opts.storeChallenge
 * @param {TUserId} [opts.userId]
 * @param {number} [opts.ttlMs]
 * @returns {Promise<{ challenge: string, options: Record<string, unknown> }>}
 */
export async function initAuthentication({
  config, allowCredentials,
  storeChallenge, userId, ttlMs,
}) {
  const { challenge, options } = generateAuthenticationOptions(config, allowCredentials);
  await storeChallenge({
    challenge,
    type: 'authentication',
    userId,
    expiresAt: challengeExpiry(ttlMs),
  });
  return { challenge, options };
}

/**
 * Step 2 of an authentication ceremony — fetch the challenge, look up
 * the credential, verify the assertion, delete the challenge, and
 * (optionally) bump the credential's clone-detection counter.
 *
 * Handles the typical "delete challenge early on credential-not-found"
 * branch so retry storms can't reuse the same challenge.
 *
 * Accepts credential rows with either `publicKey` or `public_key` keyed
 * values so it drops into both camelCase and snake_case schemas.
 *
 * @template TCredential
 * @param {Object} opts
 * @param {{ rpId: string, origin: string }} opts.config
 * @param {{ id?: string, credentialId?: string, clientDataJSON: string, authenticatorData: string, signature: string }} opts.response
 * @param {string} opts.challengeStr
 * @param {(challenge: string) => Promise<{ type: string } | null | undefined>} opts.getChallenge
 * @param {(challenge: string) => Promise<unknown>} opts.deleteChallenge
 * @param {(credentialId: string) => Promise<TCredential | null | undefined>} opts.getCredentialById
 *        Must return a row with `publicKey`/`public_key` (base64url) + `counter`.
 * @param {(credentialId: string, newCounter: number) => Promise<unknown>} [opts.updateCounter]
 * @param {string} [opts.expectedType='authentication']
 * @param {boolean} [opts.async=true] - Use `verifyAuthenticationAsync`
 *        (supports Ed25519 via Web Crypto). Set `false` for sync-only
 *        ES256 verification in environments that forbid async crypto.
 * @returns {Promise<{ credentialId: string, newCounter: number, credential: TCredential }>}
 * @throws {PasskeyFlowError}
 */
export async function runAuthenticationCeremony({
  config, response, challengeStr,
  getChallenge, deleteChallenge, getCredentialById, updateCounter,
  expectedType = 'authentication',
  async: useAsync = true,
}) {
  const stored = await getChallenge(challengeStr);
  if (!stored || stored.type !== expectedType) {
    throw new PasskeyFlowError('invalid_challenge', 'Invalid or expired challenge');
  }

  const credentialId = response.id || response.credentialId;
  const credential = await getCredentialById(credentialId);
  if (!credential) {
    await deleteChallenge(challengeStr);
    throw new PasskeyFlowError('credential_not_found', 'Credential not found');
  }

  const rawPublicKey = credential.publicKey ?? credential.public_key;
  const storedCred = {
    publicKey: rawPublicKey instanceof Uint8Array ? rawPublicKey : decodeBase64urlIgnorePadding(rawPublicKey),
    counter: credential.counter ?? 0,
  };

  let result;
  try {
    result = useAsync
      ? await verifyAuthenticationAsync(config, response, storedCred, challengeStr)
      : verifyAuthentication(config, response, storedCred, challengeStr);
  } catch (err) {
    throw new PasskeyFlowError('verification_failed', `Login verification failed: ${err.message}`);
  }

  await deleteChallenge(challengeStr);

  const newCounter = result.newCounter ?? 0;
  if (updateCounter) {
    await updateCounter(credential.id ?? credentialId, newCounter);
  }

  return {
    credentialId: result.credentialId,
    newCounter,
    credential,
  };
}
