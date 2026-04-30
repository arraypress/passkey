import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeBase64Url, decodeBase64Url,
  getConfigFromOrigin, challengeExpiry,
  initRegistration, initAuthentication,
  runRegistrationCeremony, runAuthenticationCeremony,
  PasskeyFlowError,
} from '../src/flow.js';

/** In-memory challenge store — mimics the DB closures route handlers pass in. */
function makeStore() {
  const challenges = new Map();
  return {
    challenges,
    storeChallenge: async (row) => { challenges.set(row.challenge, row); },
    getChallenge: async (c) => challenges.get(c) ?? null,
    deleteChallenge: async (c) => { challenges.delete(c); },
  };
}

// ── Encoders ─────────────────────────────

describe('encodeBase64Url / decodeBase64Url', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f]);
    const encoded = encodeBase64Url(bytes);
    assert.match(encoded, /^[A-Za-z0-9_-]+$/);
    assert.deepEqual(Array.from(decodeBase64Url(encoded)), Array.from(bytes));
  });

  it('has no base64 padding', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    assert.ok(!encodeBase64Url(bytes).includes('='));
  });
});

// ── Config helper ────────────────────────

describe('getConfigFromOrigin', () => {
  it('prefers the Origin header over the fallback URL', () => {
    const config = getConfigFromOrigin('https://app.example.com', 'https://api.example.com/admin/api');
    assert.equal(config.rpId, 'app.example.com');
    assert.equal(config.origin, 'https://app.example.com');
  });

  it('falls back to the request URL when no Origin is present', () => {
    const config = getConfigFromOrigin(null, 'https://api.example.com/admin/api');
    assert.equal(config.rpId, 'api.example.com');
    assert.equal(config.origin, 'https://api.example.com');
  });

  it('accepts a URL object as fallback', () => {
    const config = getConfigFromOrigin(undefined, new URL('https://store.test/admin'));
    assert.equal(config.rpId, 'store.test');
  });

  it('defaults rpName to the hostname', () => {
    const config = getConfigFromOrigin('https://app.example.com', '');
    assert.equal(config.rpName, 'app.example.com');
  });

  it('honours explicit rpName', () => {
    const config = getConfigFromOrigin('https://app.example.com', '', 'My Store');
    assert.equal(config.rpName, 'My Store');
    assert.equal(config.rpId, 'app.example.com');
  });
});

// ── challengeExpiry ──────────────────────

describe('challengeExpiry', () => {
  it('defaults to ~5 minutes in the future', () => {
    const iso = challengeExpiry();
    const deltaMs = new Date(iso).getTime() - Date.now();
    assert.ok(deltaMs > 4 * 60 * 1000 && deltaMs <= 5 * 60 * 1000 + 100);
  });

  it('honours a custom TTL', () => {
    const iso = challengeExpiry(60_000);
    const deltaMs = new Date(iso).getTime() - Date.now();
    assert.ok(deltaMs > 55_000 && deltaMs <= 60_100);
  });
});

// ── initRegistration / initAuthentication ──

describe('initRegistration', () => {
  it('generates options and persists the challenge', async () => {
    const store = makeStore();
    const { challenge, options } = await initRegistration({
      config: { rpName: 'Test', rpId: 'localhost' },
      user: { id: 'u1', name: 'user@test.com' },
      storeChallenge: store.storeChallenge,
      userId: 42,
      data: JSON.stringify({ email: 'user@test.com' }),
    });
    assert.ok(challenge);
    assert.equal(options.rp.id, 'localhost');
    const row = store.challenges.get(challenge);
    assert.equal(row.type, 'registration');
    assert.equal(row.userId, 42);
    assert.equal(row.data, '{"email":"user@test.com"}');
    assert.ok(row.expiresAt);
  });

  it('passes excludeCredentials through', async () => {
    const store = makeStore();
    const { options } = await initRegistration({
      config: { rpName: 'Test', rpId: 'localhost' },
      user: { id: 'u1', name: 'u@t.com' },
      exclude: ['existing-cred-id'],
      storeChallenge: store.storeChallenge,
    });
    assert.equal(options.excludeCredentials[0].id, 'existing-cred-id');
  });

  it('defaults type to "registration" and accepts overrides', async () => {
    const store = makeStore();
    await initRegistration({
      config: { rpName: 'T', rpId: 'x' },
      user: { id: 'u', name: 'u' },
      storeChallenge: store.storeChallenge,
    });
    assert.equal([...store.challenges.values()][0].type, 'registration');

    const store2 = makeStore();
    await initRegistration({
      config: { rpName: 'T', rpId: 'x' },
      user: { id: 'u', name: 'u' },
      storeChallenge: store2.storeChallenge,
      type: 'setup',
    });
    assert.equal([...store2.challenges.values()][0].type, 'setup');
  });
});

describe('initAuthentication', () => {
  it('generates options and persists with type="authentication"', async () => {
    const store = makeStore();
    const { challenge, options } = await initAuthentication({
      config: { rpId: 'localhost' },
      allowCredentials: ['c1', 'c2'],
      storeChallenge: store.storeChallenge,
      userId: 99,
    });
    assert.ok(challenge);
    assert.equal(options.allowCredentials.length, 2);
    const row = store.challenges.get(challenge);
    assert.equal(row.type, 'authentication');
    assert.equal(row.userId, 99);
  });

  it('omits allowCredentials when undefined', async () => {
    const store = makeStore();
    const { options } = await initAuthentication({
      config: { rpId: 'localhost' },
      storeChallenge: store.storeChallenge,
    });
    assert.equal(options.allowCredentials, undefined);
  });
});

// ── Ceremony runners (error paths — success paths need real crypto fixtures) ──

describe('runRegistrationCeremony', () => {
  it('throws invalid_challenge when the challenge is missing', async () => {
    const store = makeStore();
    await assert.rejects(
      runRegistrationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: {},
        challengeStr: 'missing',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
      }),
      (err) => err instanceof PasskeyFlowError && err.code === 'invalid_challenge',
    );
  });

  it('throws invalid_challenge when the type mismatches', async () => {
    const store = makeStore();
    store.challenges.set('abc', { type: 'authentication' });
    await assert.rejects(
      runRegistrationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: {},
        challengeStr: 'abc',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
      }),
      (err) => err.code === 'invalid_challenge',
    );
  });

  it('throws invalid_challenge when expectedUserId mismatches (camelCase)', async () => {
    const store = makeStore();
    store.challenges.set('abc', { type: 'registration', userId: 7 });
    await assert.rejects(
      runRegistrationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: {},
        challengeStr: 'abc',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
        expectedUserId: 8,
      }),
      (err) => err.code === 'invalid_challenge',
    );
  });

  it('accepts snake_case user_id on the stored row', async () => {
    // Match succeeds → we progress to the verifyRegistration call, which
    // then fails with verification_failed. That's enough to prove the
    // userId guard accepted snake_case.
    const store = makeStore();
    store.challenges.set('abc', { type: 'registration', user_id: 7 });
    await assert.rejects(
      runRegistrationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: { clientDataJSON: '!!!not-base64!!!', attestationObject: '!!!' },
        challengeStr: 'abc',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
        expectedUserId: 7,
      }),
      (err) => err.code === 'verification_failed',
    );
    // Challenge NOT deleted on verification failure (retryable).
    assert.ok(store.challenges.has('abc'));
  });

  it('wraps verify errors as verification_failed', async () => {
    const store = makeStore();
    store.challenges.set('xyz', { type: 'registration' });
    await assert.rejects(
      runRegistrationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: { clientDataJSON: 'bogus', attestationObject: 'bogus' },
        challengeStr: 'xyz',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
      }),
      (err) => err.code === 'verification_failed',
    );
  });
});

describe('runAuthenticationCeremony', () => {
  it('throws invalid_challenge when the challenge is missing', async () => {
    const store = makeStore();
    await assert.rejects(
      runAuthenticationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: { id: 'cred-1' },
        challengeStr: 'nope',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
        getCredentialById: async () => null,
      }),
      (err) => err.code === 'invalid_challenge',
    );
  });

  it('throws credential_not_found and deletes the challenge', async () => {
    const store = makeStore();
    store.challenges.set('abc', { type: 'authentication' });
    await assert.rejects(
      runAuthenticationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: { id: 'missing-cred' },
        challengeStr: 'abc',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
        getCredentialById: async () => null,
      }),
      (err) => err.code === 'credential_not_found',
    );
    assert.equal(store.challenges.has('abc'), false);
  });

  it('supports response.credentialId when id is absent', async () => {
    const store = makeStore();
    store.challenges.set('abc', { type: 'authentication' });
    let lookedUp;
    await assert.rejects(
      runAuthenticationCeremony({
        config: { rpId: 'localhost', origin: 'https://localhost' },
        response: { credentialId: 'fallback-cred' },
        challengeStr: 'abc',
        getChallenge: store.getChallenge,
        deleteChallenge: store.deleteChallenge,
        getCredentialById: async (id) => { lookedUp = id; return null; },
      }),
      (err) => err.code === 'credential_not_found',
    );
    assert.equal(lookedUp, 'fallback-cred');
  });
});

describe('PasskeyFlowError', () => {
  it('sets name + code', () => {
    const err = new PasskeyFlowError('invalid_challenge', 'nope');
    assert.equal(err.name, 'PasskeyFlowError');
    assert.equal(err.code, 'invalid_challenge');
    assert.equal(err.message, 'nope');
    assert.ok(err instanceof Error);
  });
});
