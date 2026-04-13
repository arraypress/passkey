/** Decode a base64url string to an ArrayBuffer. */
export function base64UrlToBuffer(base64url: string): ArrayBuffer;

/** Encode an ArrayBuffer to a base64url string (with padding). */
export function bufferToBase64Url(buffer: ArrayBuffer): string;

/** Prepare registration options for navigator.credentials.create(). */
export function prepareRegistrationOptions(serverResponse: {
  challenge: string;
  options: Record<string, any>;
}): { publicKey: Record<string, any> };

/** Prepare authentication options for navigator.credentials.get(). */
export function prepareAuthenticationOptions(serverResponse: {
  challenge: string;
  options: Record<string, any>;
}): { publicKey: Record<string, any> };

/** Encode a registration credential response for the server. */
export function encodeRegistrationResponse(credential: PublicKeyCredential): {
  id: string;
  rawId: string;
  type: string;
  attestationObject: string;
  clientDataJSON: string;
};

/** Encode an authentication credential response for the server. */
export function encodeAuthenticationResponse(credential: PublicKeyCredential): {
  id: string;
  rawId: string;
  type: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle: string | null;
};
