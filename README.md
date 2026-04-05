# @arraypress/passkey

WebAuthn passkey authentication — registration and login verification with ES256 ECDSA. Built on [oslo.js](https://oslojs.dev).

Handles server-side verification. The browser side uses `navigator.credentials.create()` and `navigator.credentials.get()`.

Works in Cloudflare Workers, Node.js 20+, Deno, and Bun.

## Installation

```bash
npm install @arraypress/passkey
```

## Usage

### Registration (sign up / add passkey)

```js
import { generateRegistrationOptions, verifyRegistration, getConfig } from '@arraypress/passkey';

const config = getConfig('https://mystore.com', 'My Store');

// 1. Generate options → send to browser
const { challenge, options } = generateRegistrationOptions(
  config,
  { id: 'user_1', name: 'admin@mystore.com', displayName: 'Admin' }
);
// Store challenge in DB with 5-min expiry

// 2. Browser calls navigator.credentials.create(options)
// 3. Browser sends response back

// 4. Verify → store credential
const result = verifyRegistration(config, response, storedChallenge);
// result = { credentialId: '...', publicKey: Uint8Array(65), counter: 0 }
// Store credentialId, publicKey, counter in database
```

### Authentication (login)

```js
import { generateAuthenticationOptions, verifyAuthentication } from '@arraypress/passkey';

// 1. Generate options → send to browser
const { challenge, options } = generateAuthenticationOptions(
  config,
  ['credentialId1', 'credentialId2'] // or omit for discoverable credentials
);
// Store challenge in DB

// 2. Browser calls navigator.credentials.get(options)
// 3. Browser sends response back

// 4. Verify → update counter
const result = verifyAuthentication(config, response, storedCredential, storedChallenge);
// result = { credentialId: '...', newCounter: 1 }
// Update counter in database
```

## API

### `generateChallenge()`

Generate a random 32-byte base64url challenge. Used internally but exported for custom flows.

### `generateRegistrationOptions(config, user, excludeCredentials?)`

Generate WebAuthn registration options for `navigator.credentials.create()`.

- `config.rpName` — Your site name
- `config.rpId` — Your hostname (e.g. `'mystore.com'`)
- `user.id` — User ID
- `user.name` — Username or email
- `user.displayName` — Display name (defaults to name)
- `excludeCredentials` — Array of existing credential IDs to prevent duplicates

Returns `{ challenge, options }`. Store the challenge, send options to the browser.

### `verifyRegistration(config, response, storedChallenge)`

Verify a registration response from the browser. Checks origin, challenge, RP ID hash, user presence, and extracts the ES256 public key.

Returns `{ credentialId, publicKey, counter }`. Store all three in your database.

### `generateAuthenticationOptions(config, allowCredentials?)`

Generate WebAuthn authentication options for `navigator.credentials.get()`.

Omit `allowCredentials` for discoverable credentials (passkeys stored on the device).

### `verifyAuthentication(config, response, storedCredential, storedChallenge)`

Verify an authentication response. Checks origin, challenge, RP ID, user presence, counter increment (clone detection), and ECDSA signature.

- `storedCredential.publicKey` — The SEC1 uncompressed public key from registration
- `storedCredential.counter` — The last known counter value

Returns `{ credentialId, newCounter }`. Update the counter in your database.

### `getConfig(url, siteName?)`

Get passkey configuration from a URL. Returns `{ rpName, rpId, origin }`.

```js
getConfig('https://mystore.com', 'My Store');
// { rpName: 'My Store', rpId: 'mystore.com', origin: 'https://mystore.com' }
```

### `isChallengeExpired(createdAt, ttlMs?)`

Check if a challenge has expired. Default TTL: 5 minutes.

### Constants

- `MAX_PASSKEYS_PER_USER` — 10
- `CHALLENGE_TTL` — 300000 (5 minutes in ms)

## Security

- **ES256 only** — ECDSA with P-256, the most widely supported WebAuthn algorithm
- **Single-use challenges** — always delete after verification
- **Counter verification** — detects cloned authenticators
- **Origin + RP ID verification** — prevents phishing
- **No attestation verification** — uses "none" format (appropriate for first-party auth)

## License

MIT
