/**
 * @arraypress/passkey
 *
 * WebAuthn passkey authentication — registration and login verification.
 * Supports ES256 (ECDSA P-256) and EdDSA (Ed25519) key types.
 * Built on oslo.js.
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
  ClientDataType, coseAlgorithmES256, coseAlgorithmEdDSA,
  coseEllipticCurveP256, coseEllipticCurveEd25519,
  COSEKeyType,
} from '@oslojs/webauthn';
import { ECDSAPublicKey, p256 } from '@oslojs/crypto/ecdsa';
import { sha256 } from '@oslojs/crypto/sha2';
import { encodeBase64url, decodeBase64url } from '@oslojs/encoding';

/**
 * Convert a DER-encoded ECDSA signature to raw format (r || s).
 * WebAuthn uses DER encoding; Web Crypto expects raw (IEEE P1363).
 */
function derToRaw(der) {
  // DER: 30 <len> 02 <r-len> <r> 02 <s-len> <s>
  let offset = 2; // skip 30 <len>
  if (der[0] !== 0x30) throw new Error('Invalid DER signature');
  offset = der[1] >= 0x80 ? 3 : 2; // handle long form length

  // Read r
  if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
  const rLen = der[offset + 1];
  const rStart = offset + 2;
  const rBytes = der.slice(rStart, rStart + rLen);

  // Read s
  offset = rStart + rLen;
  if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
  const sLen = der[offset + 1];
  const sStart = offset + 2;
  const sBytes = der.slice(sStart, sStart + sLen);

  // Pad/trim r and s to 32 bytes each (P-256)
  const raw = new Uint8Array(64);
  raw.set(rBytes.length > 32 ? rBytes.slice(rBytes.length - 32) : rBytes, 32 - Math.min(rBytes.length, 32));
  raw.set(sBytes.length > 32 ? sBytes.slice(sBytes.length - 32) : sBytes, 64 - Math.min(sBytes.length, 32));
  return raw;
}

/** Challenge TTL: 5 minutes. */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/** Max passkeys per user. */
const MAX_PASSKEYS = 10;

export const CHALLENGE_TTL = CHALLENGE_TTL_MS;
export const MAX_PASSKEYS_PER_USER = MAX_PASSKEYS;

// ── Challenges ──────────────────────────

/**
 * Generate a random challenge.
 * @returns {string} Base64url-encoded 32-byte challenge.
 */
export function generateChallenge() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return encodeBase64url(bytes);
}

// ── Registration ────────────────────────

/**
 * Generate registration options to send to the browser.
 *
 * @param {Object} config
 * @param {string} config.rpName - Relying party display name.
 * @param {string} config.rpId - Relying party ID (hostname).
 * @param {Object} user - User info for the credential.
 * @param {string} user.id - User ID (will be base64url-encoded).
 * @param {string} user.name - Username (typically email).
 * @param {string} [user.displayName] - Display name.
 * @param {Array} [excludeCredentials] - Existing credential IDs to exclude.
 * @returns {{ challenge: string, options: Object }}
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
      { type: 'public-key', alg: -7 },  // ES256 (ECDSA P-256)
      { type: 'public-key', alg: -8 },  // EdDSA (Ed25519)
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
 * Supports ES256 (ECDSA P-256) and EdDSA (Ed25519) key types.
 *
 * @param {Object} config
 * @param {string} config.rpId - Relying party ID (hostname).
 * @param {string} config.origin - Expected origin (e.g. 'https://mystore.com').
 * @param {Object} response - The credential response from navigator.credentials.create().
 * @param {string} response.clientDataJSON - Base64url-encoded client data.
 * @param {string} response.attestationObject - Base64url-encoded attestation object.
 * @param {string} storedChallenge - The challenge you stored when generating options.
 * @returns {{ credentialId: string, publicKey: Uint8Array, counter: number, keyType: string }} Verified credential data.
 * @throws {Error} If verification fails.
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
  let publicKeyBytes;
  let keyType;
  const coseKeyType = coseKey.type();

  if (coseKeyType === COSEKeyType.EC2) {
    // ES256 (ECDSA P-256)
    const ec2Key = coseKey.ec2();
    if (coseKey.algorithm() !== coseAlgorithmES256) {
      throw new Error('Unsupported EC2 algorithm: only ES256 is supported');
    }
    if (ec2Key.curve !== coseEllipticCurveP256) {
      throw new Error('Unsupported EC2 curve: only P-256 is supported');
    }
    const ecKey = new ECDSAPublicKey(p256, ec2Key.x, ec2Key.y);
    publicKeyBytes = ecKey.encodeSEC1Uncompressed();
    keyType = 'ec2';
  } else if (coseKeyType === COSEKeyType.OKP) {
    // EdDSA (Ed25519)
    const okpKey = coseKey.okp();
    if (okpKey.curve !== coseEllipticCurveEd25519) {
      throw new Error('Unsupported OKP curve: only Ed25519 is supported');
    }
    // Store raw 32-byte Ed25519 public key
    publicKeyBytes = okpKey.x;
    keyType = 'ed25519';
  } else {
    throw new Error(`Unsupported key type: ${coseKeyType}. Only EC2 (ES256) and OKP (Ed25519) are supported.`);
  }

  return {
    credentialId: encodeBase64url(authData.credential.id),
    publicKey: publicKeyBytes,
    counter: authData.signCount,
    keyType,
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
 * Supports ES256 (ECDSA P-256) and EdDSA (Ed25519) key types.
 * Detects key type from the stored public key size:
 *   - 65 bytes (SEC1 uncompressed) → ES256
 *   - 32 bytes → Ed25519
 *
 * @param {Object} config
 * @param {string} config.rpId - Relying party ID.
 * @param {string} config.origin - Expected origin.
 * @param {Object} response - The credential response from navigator.credentials.get().
 * @param {string} response.clientDataJSON - Base64url client data.
 * @param {string} response.authenticatorData - Base64url authenticator data.
 * @param {string} response.signature - Base64url signature.
 * @param {Object} storedCredential - The credential stored during registration.
 * @param {Uint8Array} storedCredential.publicKey - Public key bytes (65 for EC2, 32 for Ed25519).
 * @param {number} storedCredential.counter - Last known signature counter.
 * @param {string} storedChallenge - The challenge you stored when generating options.
 * @returns {{ credentialId: string, newCounter: number }} Verified result with updated counter.
 * @throws {Error} If verification fails.
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

  // Build the signature message (authData || hash(clientData))
  const signatureMessage = createAssertionSignatureMessage(authDataBytes, clientDataBytes);
  const signatureBytes = decodeBase64url(response.signature);

  // Detect key type from stored public key size
  const pubKeyBytes = storedCredential.publicKey;

  if (pubKeyBytes.length === 65) {
    // ES256 (ECDSA P-256) — SEC1 uncompressed: 0x04 + 32-byte X + 32-byte Y
    const hash = sha256(signatureMessage);
    const x = pubKeyBytes.slice(1, 33);
    const y = pubKeyBytes.slice(33, 65);
    const xBigInt = BigInt('0x' + Array.from(x, b => b.toString(16).padStart(2, '0')).join(''));
    const yBigInt = BigInt('0x' + Array.from(y, b => b.toString(16).padStart(2, '0')).join(''));
    const publicKey = new ECDSAPublicKey(p256, xBigInt, yBigInt);
    const valid = publicKey.verifySignature(hash, signatureBytes);
    if (!valid) {
      throw new Error('Signature verification failed');
    }
  } else if (pubKeyBytes.length === 32) {
    // Ed25519 — verify using Web Crypto API (synchronous not available in oslo)
    // Ed25519 signs the raw message, not a hash
    throw new Error('Ed25519 authentication requires async verification — use verifyAuthenticationAsync()');
  } else {
    throw new Error(`Unknown public key format (${pubKeyBytes.length} bytes)`);
  }

  return {
    credentialId: response.id || response.credentialId,
    newCounter: authData.signCount,
  };
}

/**
 * Async version of verifyAuthentication that supports Ed25519 via Web Crypto API.
 * Use this when you may have Ed25519 credentials.
 */
export async function verifyAuthenticationAsync(config, response, storedCredential, storedChallenge) {
  // Parse client data
  const clientDataBytes = decodeBase64url(response.clientDataJSON);
  const clientData = parseClientDataJSON(clientDataBytes);

  if (clientData.type !== ClientDataType.Get) {
    throw new Error('Invalid client data type: expected webauthn.get');
  }

  const challengeFromClient = encodeBase64url(clientData.challenge);
  if (challengeFromClient !== storedChallenge) {
    throw new Error('Challenge mismatch');
  }

  if (clientData.origin !== config.origin) {
    throw new Error(`Origin mismatch: expected ${config.origin}, got ${clientData.origin}`);
  }

  const authDataBytes = decodeBase64url(response.authenticatorData);
  const authData = parseAuthenticatorData(authDataBytes);

  if (!authData.verifyRelyingPartyIdHash(config.rpId)) {
    throw new Error('RP ID hash mismatch');
  }

  if (!authData.userPresent) {
    throw new Error('User presence flag not set');
  }

  if (authData.signCount !== 0 && authData.signCount <= storedCredential.counter) {
    throw new Error('Counter did not increment — possible cloned authenticator');
  }

  const signatureMessage = createAssertionSignatureMessage(authDataBytes, clientDataBytes);
  const signatureBytes = decodeBase64url(response.signature);
  const pubKeyBytes = storedCredential.publicKey;

  if (pubKeyBytes.length === 65) {
    // ES256 (SEC1 uncompressed) via Web Crypto
    // WebAuthn signatures are DER-encoded — convert to raw (r || s) for Web Crypto
    const rawSig = derToRaw(signatureBytes);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      pubKeyBytes,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      rawSig,
      signatureMessage,
    );
    if (!valid) throw new Error('Signature verification failed');
  } else if (pubKeyBytes.length === 32) {
    // Ed25519 via Web Crypto
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      pubKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const valid = await crypto.subtle.verify(
      'Ed25519',
      cryptoKey,
      signatureBytes,
      signatureMessage,
    );
    if (!valid) throw new Error('Signature verification failed');
  } else {
    throw new Error(`Unknown public key format (${pubKeyBytes.length} bytes)`);
  }

  return {
    credentialId: response.id || response.credentialId,
    newCounter: authData.signCount,
  };
}

// ── Config ──────────────────────────────

/**
 * Create a WebAuthn config from a URL.
 *
 * @param {string|URL} url - The request URL.
 * @param {string} [siteName] - Optional site name (defaults to hostname).
 * @returns {{ rpName: string, rpId: string, origin: string }}
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
 */
export function isChallengeExpired(createdAt, ttlMs = CHALLENGE_TTL_MS) {
  return Date.now() - new Date(createdAt).getTime() > ttlMs;
}
