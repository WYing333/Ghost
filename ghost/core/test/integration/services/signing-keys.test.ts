import { afterAll, beforeAll, beforeEach, describe, it } from 'vitest';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import {
  GRACE_PERIOD_MS,
  PUBLISH_DELAY_MS,
  SigningKeyService,
} from '../../../core/server/services/signing-keys/signing-key-service';
import { getPublicKeyInfo } from '../../../core/server/lib/public-jwk';

const testUtils = require('../../utils');
const models = require('../../../core/server/models');

const HOUR = 60 * 60 * 1000;

function keypair(bits: number) {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
}

const oldKeys = keypair(1024);
const strongKeys = keypair(2048);
const newKeys = [keypair(2048), keypair(2048)];

const silent = { info() {}, warn() {} };

describe('SigningKeyService (integration)', function () {
  let time: number;
  let generated: number;

  const knex = () => models.Base.knex;

  const createService = () =>
    new SigningKeyService({
      knex: knex(),
      logging: silent,
      now: () => new Date(time),
      generateKeypair: async () => {
        generated += 1;
        return newKeys[(generated - 1) % newKeys.length];
      },
    });

  const setting = async (key: string) =>
    (await knex()('settings').where('key', key).first('value')).value;

  const kid = async (pem: string) => (await getPublicKeyInfo(pem)).kid;

  const setActive = async (prefix: string, keys: { publicKey: string; privateKey: string }) => {
    await knex()('settings')
      .where('key', `${prefix}_private_key`)
      .update({ value: keys.privateKey });
    await knex()('settings').where('key', `${prefix}_public_key`).update({ value: keys.publicKey });
  };

  beforeAll(async function () {
    await testUtils.teardownDb();
    await testUtils.setup('settings')();
  });

  afterAll(testUtils.teardownDb);

  beforeEach(async function () {
    time = Date.UTC(2026, 9, 1);
    generated = 0;
    await setActive('members', oldKeys);
    await setActive('ghost', strongKeys);
    await knex()('settings')
      .whereIn('key', [
        'members_next_private_key',
        'members_previous_public_key',
        'ghost_next_private_key',
        'ghost_previous_public_key',
      ])
      .update({ value: null });
  });

  it('leaves 2048-bit keys alone', async function () {
    const service = createService();
    await setActive('members', strongKeys);
    await service.check();

    assert.equal(service.isRotating(), false);
    assert.equal(await setting('ghost_next_private_key'), null);
    const keys = await service.getVerificationKeys('staff');
    assert.deepEqual(
      keys.map((k) => k.kid),
      [await kid(strongKeys.privateKey)],
    );
  });

  it('publishes a new key for a 1024-bit key without signing with it', async function () {
    const service = createService();
    await service.check();

    assert.equal(await setting('members_next_private_key'), newKeys[0].privateKey);
    assert.equal(service.isRotating(), true);

    const signing = await service.getSigningKey('members');
    assert.equal(signing.privateKey, oldKeys.privateKey);

    const keys = await service.getVerificationKeys('members');
    assert.deepEqual(
      keys.map((k) => k.kid),
      [await kid(oldKeys.privateKey), await kid(newKeys[0].privateKey)],
    );
  });

  it('publishes only one new key when instances race', async function () {
    const first = createService();
    const second = createService();

    await Promise.all([first.check(), second.check()]);

    const next = await setting('members_next_private_key');
    assert.ok(next);
    for (const service of [first, second]) {
      const keys = await service.getVerificationKeys('members');
      assert.equal(keys[1].kid, await kid(next));
    }
  });

  it('signs with the new key once it has been published long enough', async function () {
    const service = createService();
    await service.check();

    time += PUBLISH_DELAY_MS - HOUR;
    await service.check();
    assert.equal((await service.getSigningKey('members')).privateKey, oldKeys.privateKey);

    time += HOUR;
    await service.check();

    const signing = await service.getSigningKey('members');
    assert.equal(signing.privateKey, newKeys[0].privateKey);
    assert.equal(signing.kid, await kid(newKeys[0].privateKey));

    // Settings mirror the active key so older versions keep working after a downgrade
    assert.equal(await setting('members_private_key'), newKeys[0].privateKey);
    assert.equal(await setting('members_public_key'), newKeys[0].publicKey);
    assert.equal(await setting('members_next_private_key'), null);
    assert.equal(await setting('members_previous_public_key'), oldKeys.publicKey);

    const keys = await service.getVerificationKeys('members');
    assert.deepEqual(
      keys.map((k) => k.kid),
      [await kid(newKeys[0].privateKey), await kid(oldKeys.privateKey)],
    );

    // The new key is 2048-bit, so no further rotation starts
    assert.equal(generated, 1);
  });

  it('promotes once when instances race', async function () {
    await createService().check();
    time += PUBLISH_DELAY_MS;

    const first = createService();
    const second = createService();
    await Promise.all([first.check(), second.check()]);

    assert.equal(await setting('members_private_key'), newKeys[0].privateKey);
    assert.equal(await setting('members_previous_public_key'), oldKeys.publicKey);
    assert.equal(await setting('members_next_private_key'), null);
  });

  it('keeps verifying old tokens through the grace period, then retires the old key', async function () {
    const service = createService();
    await service.check();

    const token = jwt.sign({ sub: 'member@example.com' }, oldKeys.privateKey, {
      algorithm: 'RS512',
      keyid: await kid(oldKeys.privateKey),
    });

    time += PUBLISH_DELAY_MS;
    await service.check();

    const verify = async () => {
      const keys = await service.getVerificationKeys('members');
      const key = keys.find((k) => k.kid === jwt.decode(token, { complete: true })?.header.kid);
      return key && jwt.verify(token, key.publicKey, { ignoreExpiration: true });
    };

    time += GRACE_PERIOD_MS - 1;
    await service.check();
    assert.ok(await verify());

    assert.equal(service.isRotating(), true);

    time += 1;
    await service.check();
    assert.equal(service.isRotating(), false);
    assert.equal(await setting('members_previous_public_key'), null);
    assert.equal(await verify(), undefined);
    assert.deepEqual(
      (await service.getVerificationKeys('members')).map((k) => k.kid),
      [await kid(newKeys[0].privateKey)],
    );
  });

  it('rotates the staff key the same way', async function () {
    await setActive('ghost', oldKeys);
    const service = createService();
    await service.check();

    time += PUBLISH_DELAY_MS;
    await service.check();

    assert.equal(
      (await service.getSigningKey('staff')).privateKey,
      await setting('ghost_private_key'),
    );
    assert.notEqual(await setting('ghost_private_key'), oldKeys.privateKey);
    assert.equal(await setting('ghost_previous_public_key'), oldKeys.publicKey);
  });
});
