/**
 * @arraypress/passkey/browser
 *
 * Browser-side WebAuthn helpers for use with @arraypress/passkey.
 * These convert between base64url strings (used by the server) and
 * ArrayBuffers (used by the WebAuthn browser API).
 *
 * @module @arraypress/passkey/browser
 */

/**
 * Decode a base64url string to an ArrayBuffer.
 * Used to convert challenges and credential IDs for navigator.credentials.
 *
 * @param {string} base64url - Base64url-encoded string (with or without padding).
 * @returns {ArrayBuffer}
 */
export function base64UrlToBuffer(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/**
 * Encode an ArrayBuffer to a base64url string WITH padding.
 * The @oslojs/encoding library used by the server requires padding.
 *
 * @param {ArrayBuffer} buffer - Raw bytes from WebAuthn API.
 * @returns {string} Base64url-encoded string with padding.
 */
export function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Prepare WebAuthn registration options for navigator.credentials.create().
 * Converts base64url strings from the server response to ArrayBuffers.
 *
 * @param {{ challenge: string, options: object }} serverResponse - From POST /auth/setup or /passkeys/register/options
 * @returns {{ publicKey: object }} Ready to pass to navigator.credentials.create()
 */
export function prepareRegistrationOptions({ challenge, options }) {
  return {
    publicKey: {
      ...options,
      challenge: base64UrlToBuffer(challenge),
      user: {
        ...options.user,
        id: base64UrlToBuffer(options.user.id),
      },
      excludeCredentials: (options.excludeCredentials || []).map(c => ({
        ...c,
        id: base64UrlToBuffer(c.id),
      })),
    },
  };
}

/**
 * Prepare WebAuthn authentication options for navigator.credentials.get().
 * Converts base64url strings from the server response to ArrayBuffers.
 *
 * @param {{ challenge: string, options: object }} serverResponse - From POST /auth/login/options
 * @returns {{ publicKey: object }} Ready to pass to navigator.credentials.get()
 */
export function prepareAuthenticationOptions({ challenge, options }) {
  return {
    publicKey: {
      ...options,
      challenge: base64UrlToBuffer(challenge),
      allowCredentials: (options.allowCredentials || []).map(c => ({
        ...c,
        id: base64UrlToBuffer(c.id),
      })),
    },
  };
}

/**
 * Encode a registration credential response for sending to the server.
 *
 * @param {PublicKeyCredential} credential - From navigator.credentials.create()
 * @returns {object} Encoded response for POST /auth/setup/verify or /passkeys/register/verify
 */
export function encodeRegistrationResponse(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    attestationObject: bufferToBase64Url(response.attestationObject),
    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
  };
}

/**
 * Encode an authentication credential response for sending to the server.
 *
 * @param {PublicKeyCredential} credential - From navigator.credentials.get()
 * @returns {object} Encoded response for POST /auth/login/verify
 */
export function encodeAuthenticationResponse(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorData: bufferToBase64Url(response.authenticatorData),
    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
    signature: bufferToBase64Url(response.signature),
    userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
  };
}
