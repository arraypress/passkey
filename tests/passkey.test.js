import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateChallenge, generateRegistrationOptions, generateAuthenticationOptions,
  getConfig, isChallengeExpired, verifyRegistration, verifyAuthentication,
  MAX_PASSKEYS_PER_USER, CHALLENGE_TTL,
} from '../src/index.js';

describe('generateChallenge', () => {
  it('returns a base64url string', () => {
    const challenge = generateChallenge();
    assert.ok(challenge.length > 20);
    assert.match(challenge, /^[A-Za-z0-9_=-]+$/);
  });

  it('generates unique challenges', () => {
    const a = generateChallenge();
    const b = generateChallenge();
    assert.notEqual(a, b);
  });
});

describe('generateRegistrationOptions', () => {
  it('returns challenge and options', () => {
    const { challenge, options } = generateRegistrationOptions(
      { rpName: 'Test', rpId: 'localhost' },
      { id: 'user_1', name: 'test@example.com', displayName: 'Test User' }
    );

    assert.ok(challenge);
    assert.equal(options.rp.name, 'Test');
    assert.equal(options.rp.id, 'localhost');
    assert.ok(options.user.id); // base64url encoded
    assert.equal(options.user.name, 'test@example.com');
    assert.equal(options.user.displayName, 'Test User');
    assert.equal(options.pubKeyCredParams[0].alg, -7); // ES256
    assert.equal(options.timeout, 300000);
  });

  it('includes excludeCredentials', () => {
    const { options } = generateRegistrationOptions(
      { rpName: 'Test', rpId: 'localhost' },
      { id: 'u1', name: 'test@example.com' },
      ['cred1', 'cred2']
    );

    assert.equal(options.excludeCredentials.length, 2);
    assert.equal(options.excludeCredentials[0].id, 'cred1');
    assert.equal(options.excludeCredentials[0].type, 'public-key');
  });

  it('defaults displayName to name', () => {
    const { options } = generateRegistrationOptions(
      { rpName: 'Test', rpId: 'localhost' },
      { id: 'u1', name: 'user@test.com' }
    );
    assert.equal(options.user.displayName, 'user@test.com');
  });
});

describe('generateAuthenticationOptions', () => {
  it('returns challenge and options', () => {
    const { challenge, options } = generateAuthenticationOptions({ rpId: 'localhost' });

    assert.ok(challenge);
    assert.equal(options.rpId, 'localhost');
    assert.equal(options.timeout, 300000);
    assert.equal(options.allowCredentials, undefined); // discoverable
  });

  it('includes allowCredentials when provided', () => {
    const { options } = generateAuthenticationOptions(
      { rpId: 'localhost' },
      ['cred1', 'cred2']
    );

    assert.equal(options.allowCredentials.length, 2);
    assert.equal(options.allowCredentials[0].id, 'cred1');
  });

  it('omits allowCredentials for discoverable', () => {
    const { options } = generateAuthenticationOptions({ rpId: 'localhost' });
    assert.equal(options.allowCredentials, undefined);
  });
});

describe('getConfig', () => {
  it('parses https URL', () => {
    const config = getConfig('https://mystore.com');
    assert.equal(config.rpName, 'mystore.com');
    assert.equal(config.rpId, 'mystore.com');
    assert.equal(config.origin, 'https://mystore.com');
  });

  it('parses localhost with port', () => {
    const config = getConfig('http://localhost:8787');
    assert.equal(config.rpId, 'localhost');
    assert.equal(config.origin, 'http://localhost:8787');
  });

  it('uses custom site name', () => {
    const config = getConfig('https://mystore.com', 'My Store');
    assert.equal(config.rpName, 'My Store');
    assert.equal(config.rpId, 'mystore.com');
  });

  it('accepts URL object', () => {
    const config = getConfig(new URL('https://example.com'));
    assert.equal(config.rpId, 'example.com');
  });
});

describe('isChallengeExpired', () => {
  it('returns false for recent challenge', () => {
    assert.equal(isChallengeExpired(new Date().toISOString()), false);
  });

  it('returns true for old challenge', () => {
    const old = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 min ago
    assert.equal(isChallengeExpired(old), true);
  });

  it('respects custom TTL', () => {
    const recent = new Date(Date.now() - 2000).toISOString(); // 2 sec ago
    assert.equal(isChallengeExpired(recent, 1000), true);  // 1 sec TTL
    assert.equal(isChallengeExpired(recent, 5000), false);  // 5 sec TTL
  });
});

describe('verifyRegistration', () => {
  it('throws on invalid client data', () => {
    // Invalid base64url should throw
    assert.throws(() => {
      verifyRegistration(
        { rpId: 'localhost', origin: 'http://localhost' },
        { clientDataJSON: 'not-valid-base64url!!!', attestationObject: 'also-bad' },
        'challenge'
      );
    });
  });
});

describe('verifyAuthentication', () => {
  it('throws on invalid client data', () => {
    assert.throws(() => {
      verifyAuthentication(
        { rpId: 'localhost', origin: 'http://localhost' },
        { credentialId: 'x', clientDataJSON: 'bad', authenticatorData: 'bad', signature: 'bad' },
        { publicKey: new Uint8Array(65), counter: 0 },
        'challenge'
      );
    });
  });
});

describe('constants', () => {
  it('MAX_PASSKEYS_PER_USER is 10', () => {
    assert.equal(MAX_PASSKEYS_PER_USER, 10);
  });

  it('CHALLENGE_TTL is 5 minutes', () => {
    assert.equal(CHALLENGE_TTL, 300000);
  });
});
