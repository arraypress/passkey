/**
 * @arraypress/passkey
 *
 * WebAuthn passkey authentication — registration and login verification.
 * Uses ES256 (ECDSA P-256) for signatures. Built on oslo.js.
 *
 * This package handles the SERVER-SIDE verification. The browser side
 * uses `navigator.credentials.create()` and `navigator.credentials.get()`.
 *
 * Works in Cloudflare Workers, Node.js 20+, Deno, and Bun.
 *
 * @module @arraypress/passkey
 */

import {
  parseAttestationObject, parseAuthenticatorData, parseClientDataJSON,
  createAssertionSignatureMessage,
  ClientDataType, coseAlgorithmES256, coseEllipticCurveP256,
  COSEKeyType,
} from '@oslojs/webauthn';
import { ECDSAPublicKey, p256 } from '@oslojs/crypto/ecdsa';
import { sha256 } from '@oslojs/crypto/sha2';
import { encodeBase64url, decodeBase64url } from '@oslojs/encoding';

/** Challenge TTL: 5 minutes. */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/** Max passkeys per user. */
const MAX_PASSKEYS = 10;

// ── Challenge Generation ─────────────────

/**
 * Generate a random challenge for WebAuthn registration or authentication.
 *
 * @returns {string} Base64url-encoded 32-byte random challenge.
 *
 * @example
 * const challenge = generateChallenge();
 * // Store in database with 5-minute expiry, send to client
 */
export function generateChallenge() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return encodeBase64url(bytes);
}

// ── Registration ─────────────────────────

/**
 * Generate registration options to send to the browser.
 *
 * @param {Object} config
 * @param {string} config.rpName - Relying party name (your site name).
 * @param {string} config.rpId - Relying party ID (hostname, e.g. 'example.com').
 * @param {Object} user
 * @param {string} user.id - User ID.
 * @param {string} user.name - Username or email.
 * @param {string} user.displayName - Display name.
 * @param {Array} [excludeCredentials] - Existing credential IDs to prevent duplicates.
 * @returns {{ challenge: string, options: Object }} Challenge + options for navigator.credentials.create().
 *
 * @example
 * const { challenge, options } = generateRegistrationOptions(
 *   { rpName: 'My Store', rpId: 'mystore.com' },
 *   { id: 'user_1', name: 'admin@mystore.com', displayName: 'Admin' }
 * );
 * // Store challenge in DB, send options to client
 */
export function generateRegistrationOptions(config, user, excludeCredentials = []) {
  const challenge = generateChallenge();

  const options = {
    challenge,
    rp: { name: config.rpName, id: config.rpId },
    user: {
      id: encodeBase64url(new TextEncoder().encode(user.id)),
      name: user.name,
      displayName: user.displayName || user.name,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
    ],
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    timeout: 300000, // 5 minutes
    excludeCredentials: excludeCredentials.map(id => ({
      type: 'public-key',
      id,
    })),
  };

  return { challenge, options };
}

/**
 * Verify a registration response from the browser.
 *
 * @param {Object} config
 * @param {string} config.rpId - Relying party ID (hostname).
 * @param {string} config.origin - Expected origin (e.g. 'https://mystore.com').
 * @param {Object} response - The credential response from navigator.credentials.create().
 * @param {string} response.clientDataJSON - Base64url-encoded client data.
 * @param {string} response.attestationObject - Base64url-encoded attestation object.
 * @param {string} storedChallenge - The challenge you stored when generating options.
 * @returns {{ credentialId: string, publicKey: Uint8Array, counter: number }} Verified credential data.
 * @throws {Error} If verification fails.
 *
 * @example
 * const result = verifyRegistration(
 *   { rpId: 'mystore.com', origin: 'https://mystore.com' },
 *   { clientDataJSON: '...', attestationObject: '...' },
 *   storedChallenge
 * );
 * // Store result.credentialId, result.publicKey, result.counter in database
 */
export function verifyRegistration(config, response, storedChallenge) {
  // Parse client data
  const clientDataBytes = decodeBase64url(response.clientDataJSON);
  const clientData = parseClientDataJSON(clientDataBytes);

  // Verify client data
  if (clientData.type !== ClientDataType.Create) {
    throw new Error('Invalid client data type: expected webauthn.create');
  }

  // Verify challenge
  const challengeFromClient = encodeBase64url(clientData.challenge);
  if (challengeFromClient !== storedChallenge) {
    throw new Error('Challenge mismatch');
  }

  // Verify origin
  if (clientData.origin !== config.origin) {
    throw new Error(`Origin mismatch: expected ${config.origin}, got ${clientData.origin}`);
  }

  // Parse attestation object
  const attestationBytes = decodeBase64url(response.attestationObject);
  const attestation = parseAttestationObject(attestationBytes);
  const authData = attestation.authenticatorData;

  // Verify RP ID hash
  if (!authData.verifyRelyingPartyIdHash(config.rpId)) {
    throw new Error('RP ID hash mismatch');
  }

  // Verify user present flag
  if (!authData.userPresent) {
    throw new Error('User presence flag not set');
  }

  // Extract credential
  if (!authData.credential) {
    throw new Error('No credential in authenticator data');
  }

  const coseKey = authData.credential.publicKey;

  // Verify it's an EC key with P-256
  if (coseKey.keyType !== COSEKeyType.EC2) {
    throw new Error('Unsupported key type: only EC2 (ECDSA) is supported');
  }
  if (coseKey.algorithm !== coseAlgorithmES256) {
    throw new Error('Unsupported algorithm: only ES256 is supported');
  }
  if (coseKey.curve !== coseEllipticCurveP256) {
    throw new Error('Unsupported curve: only P-256 is supported');
  }

  // Encode public key as SEC1 uncompressed (65 bytes: 0x04 + X + Y)
  const ecKey = new ECDSAPublicKey(p256, coseKey.x, coseKey.y);
  const publicKeyBytes = ecKey.encodeSEC1Uncompressed();

  return {
    credentialId: encodeBase64url(authData.credential.id),
    publicKey: publicKeyBytes,
    counter: authData.signCount,
  };
}

// ── Authentication ───────────────────────

/**
 * Generate authentication options to send to the browser.
 *
 * @param {Object} config
 * @param {string} config.rpId - Relying party ID.
 * @param {Array} [allowCredentials] - Credential IDs to allow (omit for discoverable credentials).
 * @returns {{ challenge: string, options: Object }}
 *
 * @example
 * const { challenge, options } = generateAuthenticationOptions(
 *   { rpId: 'mystore.com' },
 *   ['credId1', 'credId2'] // or omit for discoverable
 * );
 */
export function generateAuthenticationOptions(config, allowCredentials) {
  const challenge = generateChallenge();

  const options = {
    challenge,
    rpId: config.rpId,
    timeout: 300000,
    userVerification: 'preferred',
  };

  if (allowCredentials && allowCredentials.length > 0) {
    options.allowCredentials = allowCredentials.map(id => ({
      type: 'public-key',
      id,
    }));
  }

  return { challenge, options };
}

/**
 * Verify an authentication response from the browser.
 *
 * @param {Object} config
 * @param {string} config.rpId - Relying party ID.
 * @param {string} config.origin - Expected origin.
 * @param {Object} response - The credential response from navigator.credentials.get().
 * @param {string} response.credentialId - Base64url credential ID.
 * @param {string} response.clientDataJSON - Base64url client data.
 * @param {string} response.authenticatorData - Base64url authenticator data.
 * @param {string} response.signature - Base64url signature.
 * @param {Object} storedCredential - The credential stored during registration.
 * @param {Uint8Array} storedCredential.publicKey - SEC1 uncompressed public key.
 * @param {number} storedCredential.counter - Last known signature counter.
 * @param {string} storedChallenge - The challenge you stored when generating options.
 * @returns {{ credentialId: string, newCounter: number }} Verified result with updated counter.
 * @throws {Error} If verification fails (signature, challenge, origin, counter).
 *
 * @example
 * const result = verifyAuthentication(
 *   { rpId: 'mystore.com', origin: 'https://mystore.com' },
 *   { credentialId: '...', clientDataJSON: '...', authenticatorData: '...', signature: '...' },
 *   { publicKey: storedPublicKey, counter: storedCounter },
 *   storedChallenge
 * );
 * // Update counter in database: result.newCounter
 */
export function verifyAuthentication(config, response, storedCredential, storedChallenge) {
  // Parse client data
  const clientDataBytes = decodeBase64url(response.clientDataJSON);
  const clientData = parseClientDataJSON(clientDataBytes);

  // Verify type
  if (clientData.type !== ClientDataType.Get) {
    throw new Error('Invalid client data type: expected webauthn.get');
  }

  // Verify challenge
  const challengeFromClient = encodeBase64url(clientData.challenge);
  if (challengeFromClient !== storedChallenge) {
    throw new Error('Challenge mismatch');
  }

  // Verify origin
  if (clientData.origin !== config.origin) {
    throw new Error(`Origin mismatch: expected ${config.origin}, got ${clientData.origin}`);
  }

  // Parse authenticator data
  const authDataBytes = decodeBase64url(response.authenticatorData);
  const authData = parseAuthenticatorData(authDataBytes);

  // Verify RP ID hash
  if (!authData.verifyRelyingPartyIdHash(config.rpId)) {
    throw new Error('RP ID hash mismatch');
  }

  // Verify user present
  if (!authData.userPresent) {
    throw new Error('User presence flag not set');
  }

  // Verify counter (clone detection)
  if (authData.signCount !== 0 && authData.signCount <= storedCredential.counter) {
    throw new Error('Counter did not increment — possible cloned authenticator');
  }

  // Verify signature
  const signatureMessage = createAssertionSignatureMessage(authDataBytes, clientDataBytes);
  const hash = sha256(signatureMessage);

  const signatureBytes = decodeBase64url(response.signature);

  // Decode stored public key (SEC1 uncompressed)
  const publicKey = ECDSAPublicKey.decodeSEC1Uncompressed(p256, storedCredential.publicKey);

  // Verify ECDSA signature
  const valid = publicKey.verifySignature(hash, signatureBytes);
  if (!valid) {
    throw new Error('Signature verification failed');
  }

  return {
    credentialId: response.credentialId,
    newCounter: authData.signCount,
  };
}

// ── Utilities ────────────────────────────

/**
 * Get passkey configuration from a URL.
 *
 * @param {string|URL} url - The site URL.
 * @param {string} [siteName] - Optional site name (defaults to hostname).
 * @returns {{ rpName: string, rpId: string, origin: string }}
 *
 * @example
 * getConfig('https://mystore.com');
 * // { rpName: 'mystore.com', rpId: 'mystore.com', origin: 'https://mystore.com' }
 *
 * getConfig('http://localhost:8787', 'My Store');
 * // { rpName: 'My Store', rpId: 'localhost', origin: 'http://localhost:8787' }
 */
export function getConfig(url, siteName) {
  const parsed = typeof url === 'string' ? new URL(url) : url;
  return {
    rpName: siteName || parsed.hostname,
    rpId: parsed.hostname,
    origin: parsed.origin,
  };
}

/**
 * Check if a challenge has expired.
 *
 * @param {string} createdAt - ISO datetime when the challenge was created.
 * @param {number} [ttlMs=300000] - Time-to-live in milliseconds (default: 5 minutes).
 * @returns {boolean} True if expired.
 *
 * @example
 * isChallengeExpired('2026-04-05T12:00:00Z'); // true if > 5 minutes ago
 */
export function isChallengeExpired(createdAt, ttlMs = CHALLENGE_TTL_MS) {
  return Date.now() - new Date(createdAt).getTime() > ttlMs;
}

/** Maximum passkeys allowed per user. */
export const MAX_PASSKEYS_PER_USER = MAX_PASSKEYS;

/** Challenge time-to-live in milliseconds. */
export const CHALLENGE_TTL = CHALLENGE_TTL_MS;
