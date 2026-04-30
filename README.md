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

## Flow helpers — `@arraypress/passkey/flow`

Route handlers end up duplicating the same orchestration: read the `Origin` header, persist a challenge, fetch it back, verify, delete. The `/flow` sub-export wraps that glue so each endpoint is one call.

```js
import {
  initRegistration, runRegistrationCeremony,
  initAuthentication, runAuthenticationCeremony,
  getConfigFromOrigin, encodeBase64Url,
  PasskeyFlowError,
} from '@arraypress/passkey/flow';

// Storage is pluggable — pass closures that hit your DB.
const storage = {
  storeChallenge: (row) => db.insertInto('challenges').values(row).execute(),
  getChallenge:   (c)   => db.selectFrom('challenges').where('challenge', '=', c).executeTakeFirst(),
  deleteChallenge:(c)   => db.deleteFrom('challenges').where('challenge', '=', c).execute(),
};

// Register — step 1
app.post('/register/options', async (c) => {
  const config = getConfigFromOrigin(c.req.header('origin'), c.req.url, 'My Store');
  return c.json(await initRegistration({
    config, user: { id: String(userId), name: email },
    storeChallenge: storage.storeChallenge,
    userId,
  }));
});

// Register — step 2
app.post('/register/verify', async (c) => {
  const { challenge, response } = await c.req.json();
  const config = getConfigFromOrigin(c.req.header('origin'), c.req.url, 'My Store');
  try {
    const result = await runRegistrationCeremony({
      config, response, challengeStr: challenge, ...storage,
      expectedUserId: userId, // rejects cross-user replay
    });
    await db.insertInto('credentials').values({
      id: result.credentialId,
      user_id: userId,
      public_key: result.publicKeyBase64, // already encoded, ready for DB
      counter: result.counter,
    }).execute();
    return c.json({ ok: true });
  } catch (err) {
    if (err instanceof PasskeyFlowError) return c.json({ error: err.message }, 400);
    throw err;
  }
});
```

### `getConfigFromOrigin(originHeader, fallbackUrl, rpName?)`

Derive a `PasskeyConfig` preferring the browser's `Origin` header — necessary when the frontend (e.g. `localhost:5174`) and backend (`localhost:8787`) are on different ports in dev. Falls back to the request URL when the header is absent.

### `initRegistration({ config, user, exclude?, storeChallenge, type?, userId?, data?, ttlMs? })`

Generate registration options and persist the challenge. Returns `{ challenge, options }`. The `data` blob is stored alongside the challenge — handy for first-run setup flows that stash `{ email, name }` on the challenge before the user row exists.

### `runRegistrationCeremony({ config, response, challengeStr, getChallenge, deleteChallenge, expectedType?, expectedUserId? })`

Fetch the stored challenge, verify the browser's attestation, delete the challenge on success. Returns `VerifiedRegistration` plus `publicKeyBase64` (ready to persist) and the original `data` blob. Throws `PasskeyFlowError` with `code`:

- `invalid_challenge` — missing, wrong type, or `expectedUserId` mismatch → map to HTTP 400
- `verification_failed` — cryptographic verification rejected → map to HTTP 400 (challenge NOT deleted, so the user can retry)

### `initAuthentication({ config, allowCredentials?, storeChallenge, userId?, ttlMs? })`

Generate authentication options and persist the challenge. Returns `{ challenge, options }`. Pass `allowCredentials` to narrow the browser's prompt; omit for discoverable credentials.

### `runAuthenticationCeremony({ config, response, challengeStr, getChallenge, deleteChallenge, getCredentialById, updateCounter?, expectedType?, async? })`

Fetch the challenge, look up the credential, verify the assertion, delete the challenge, optionally bump the clone-detection counter. Accepts rows with either `publicKey` or `public_key` keys (camel/snake drop-in). Throws `PasskeyFlowError`:

- `invalid_challenge` — map to 400
- `credential_not_found` — map to 400 (challenge IS deleted — prevents retry storms)
- `verification_failed` — map to 400

`async: true` (default) calls `verifyAuthenticationAsync` which supports Ed25519 via Web Crypto. Set `false` for sync-only ES256.

### `encodeBase64Url(buf)` / `decodeBase64Url(str)`

Base64url encoding/decoding without padding — what browsers emit and what you should persist. Decoder is padding-tolerant.

### `challengeExpiry(ttlMs?)`

ISO-8601 timestamp `ttlMs` in the future (default 5 minutes). Convenience wrapper for the `expiresAt` column on your challenge table.

## Security

- **ES256 only** — ECDSA with P-256, the most widely supported WebAuthn algorithm
- **Single-use challenges** — always delete after verification
- **Counter verification** — detects cloned authenticators
- **Origin + RP ID verification** — prevents phishing
- **No attestation verification** — uses "none" format (appropriate for first-party auth)

## License

MIT
