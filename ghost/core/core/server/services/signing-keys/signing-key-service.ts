import crypto from 'node:crypto';
import { promisify } from 'node:util';
import type { Knex } from 'knex';
import * as errors from '@tryghost/errors';
import { getPublicKeyInfo, type PublicRsaJwk } from '../../lib/public-jwk';
import { fromDatabaseDate, toDatabaseDate } from '../../lib/db-types/date';

export type SigningKeyPurpose = 'members' | 'staff';

export interface SigningKey {
  privateKey: string;
  kid: string;
}

export interface VerificationKey {
  kid: string;
  jwk: PublicRsaJwk;
  publicKey: string;
}

/** Signing and verification keys for one purpose. */
export interface SigningKeyProvider {
  getSigningKey(): Promise<SigningKey>;
  getVerificationKeys(): Promise<VerificationKey[]>;
}

interface Keypair {
  publicKey: string;
  privateKey: string;
}

interface Logger {
  info(message: string): void;
  warn(message: string): void;
}

interface PurposeState {
  active: string | null;
  next: { privateKey: string; publishedAt: Date } | null;
  previous: { publicKey: string; since: Date } | null;
}

const HOUR = 60 * 60 * 1000;

export const MIN_MODULUS_LENGTH = 2048;
// Twice the 24h JWKS cache, so verifiers have the next key before it signs anything
export const PUBLISH_DELAY_MS = 48 * HOUR;
// Covers tokens (<=10m) signed by an instance that hasn't refreshed yet (<=1h)
export const GRACE_PERIOD_MS = 2 * HOUR;

const SETTING_PREFIX: Record<SigningKeyPurpose, string> = {
  members: 'members',
  staff: 'ghost',
};

const PURPOSES = Object.keys(SETTING_PREFIX) as SigningKeyPurpose[];

function settingKeys(purpose: SigningKeyPurpose) {
  const prefix = SETTING_PREFIX[purpose];
  return {
    active: `${prefix}_private_key`,
    activePublic: `${prefix}_public_key`,
    next: `${prefix}_next_private_key`,
    previous: `${prefix}_previous_public_key`,
  };
}

const generateKeyPair = promisify(crypto.generateKeyPair);

async function generateKeypair(): Promise<Keypair> {
  // PKCS#1 PEM, matching the format of existing keys
  return generateKeyPair('rsa', {
    modulusLength: MIN_MODULUS_LENGTH,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
}

// Only for private PEMs: Node 24.20+ can't re-export a key parsed from a PKCS#1 public PEM
function toPublicPem(privateKey: string): string {
  return crypto.createPublicKey(privateKey).export({ type: 'pkcs1', format: 'pem' }).toString();
}

function modulusLength(privateKey: string): number {
  return crypto.createPrivateKey(privateKey).asymmetricKeyDetails?.modulusLength ?? 0;
}

/**
 * Rotates the site signing keypairs, which live in settings so older Ghost
 * versions keep reading the active key.
 *
 * A rotation starts when an active key is under 2048 bits. The next key is
 * published in the JWKS for PUBLISH_DELAY_MS before it signs anything; after
 * the switch the old public key stays published for GRACE_PERIOD_MS. Every
 * write is conditional on the value it replaces, so instances sharing a
 * database can't generate or promote two different keys.
 */
export class SigningKeyService {
  private knex: Knex;
  private logging: Logger;
  private now: () => Date;
  private generateKeypair: () => Promise<Keypair>;
  private state: Record<SigningKeyPurpose, PurposeState> | null = null;

  constructor({
    knex,
    logging,
    now = () => new Date(),
    generateKeypair: generate = generateKeypair,
  }: {
    knex: Knex;
    logging: Logger;
    now?: () => Date;
    generateKeypair?: () => Promise<Keypair>;
  }) {
    this.knex = knex;
    this.logging = logging;
    this.now = now;
    this.generateKeypair = generate;
  }

  /** Advances any rotation that's due, then reloads the keys. */
  async check(): Promise<void> {
    for (const purpose of PURPOSES) {
      await this.load();
      await this.retirePrevious(purpose);
      await this.promoteNext(purpose);
      await this.startRotation(purpose);
    }
    await this.load();
  }

  /** Whether any key still has a rotation step ahead of it. */
  isRotating(): boolean {
    return PURPOSES.some((purpose) => {
      const { active, next, previous } = this.getState(purpose);
      return !!next || !!previous || (!!active && modulusLength(active) < MIN_MODULUS_LENGTH);
    });
  }

  forPurpose(purpose: SigningKeyPurpose): SigningKeyProvider {
    return {
      getSigningKey: () => this.getSigningKey(purpose),
      getVerificationKeys: () => this.getVerificationKeys(purpose),
    };
  }

  async getSigningKey(purpose: SigningKeyPurpose): Promise<SigningKey> {
    const privateKey = this.getState(purpose).active;
    if (!privateKey) {
      throw new errors.IncorrectUsageError({ message: `No ${purpose} signing key` });
    }
    const { kid } = await getPublicKeyInfo(privateKey);
    return { privateKey, kid };
  }

  /** Every published key, the signing key first. */
  async getVerificationKeys(purpose: SigningKeyPurpose): Promise<VerificationKey[]> {
    const { active, next, previous } = this.getState(purpose);
    const publicPems = [active, next?.privateKey]
      .filter((pem): pem is string => !!pem)
      .map(toPublicPem);
    if (previous) {
      publicPems.push(previous.publicKey);
    }

    return Promise.all(
      publicPems.map(async (publicKey) => {
        const { kid, jwk } = await getPublicKeyInfo(publicKey);
        return { kid, jwk, publicKey };
      }),
    );
  }

  private getState(purpose: SigningKeyPurpose): PurposeState {
    if (!this.state) {
      throw new errors.IncorrectUsageError({
        message: 'Signing keys used before init(). Call init() from boot first.',
      });
    }
    return this.state[purpose];
  }

  private async load(): Promise<void> {
    const keys = PURPOSES.flatMap((purpose) => Object.values(settingKeys(purpose)));
    const rows: { key: string; value: string | null; created_at: unknown; updated_at: unknown }[] =
      await this.knex('settings')
        .whereIn('key', keys)
        .select('key', 'value', 'created_at', 'updated_at');
    const byKey = new Map(rows.map((row) => [row.key, row]));

    const changedAt = (key: string) => {
      const row = byKey.get(key);
      return fromDatabaseDate((row?.updated_at ?? row?.created_at) as Date);
    };

    const state = {} as Record<SigningKeyPurpose, PurposeState>;
    for (const purpose of PURPOSES) {
      const k = settingKeys(purpose);
      const next = byKey.get(k.next)?.value;
      const previous = byKey.get(k.previous)?.value;
      state[purpose] = {
        active: byKey.get(k.active)?.value || null,
        next: next ? { privateKey: next, publishedAt: changedAt(k.next) } : null,
        previous: previous ? { publicKey: previous, since: changedAt(k.previous) } : null,
      };
    }
    this.state = state;
  }

  private write(trx: Knex, key: string, from: string | null, to: string | null) {
    const query = trx('settings').where('key', key);
    if (from === null) {
      query.whereNull('value');
    } else {
      query.where('value', from);
    }
    return query.update({ value: to, updated_at: toDatabaseDate(this.now()) });
  }

  private async retirePrevious(purpose: SigningKeyPurpose): Promise<void> {
    const { previous } = this.getState(purpose);
    if (!previous || this.now().getTime() - previous.since.getTime() < GRACE_PERIOD_MS) {
      return;
    }

    const updated = await this.write(
      this.knex,
      settingKeys(purpose).previous,
      previous.publicKey,
      null,
    );
    this.logging.info(
      updated
        ? `Signing keys: retired previous ${purpose} key`
        : `Signing keys: previous ${purpose} key already retired`,
    );
  }

  private async promoteNext(purpose: SigningKeyPurpose): Promise<void> {
    const { active, next } = this.getState(purpose);
    if (!next || this.now().getTime() - next.publishedAt.getTime() < PUBLISH_DELAY_MS) {
      return;
    }
    if (!active) {
      this.logging.warn(`Signing keys: no active ${purpose} key to replace`);
      return;
    }

    const k = settingKeys(purpose);
    const promoted = await this.knex.transaction(async (trx) => {
      // Claims the promotion; zero rows means another instance got here first
      if (!(await this.write(trx, k.active, active, next.privateKey))) {
        return false;
      }
      await trx('settings')
        .where('key', k.activePublic)
        .update({ value: toPublicPem(next.privateKey), updated_at: toDatabaseDate(this.now()) });
      await trx('settings')
        .where('key', k.previous)
        .update({ value: toPublicPem(active), updated_at: toDatabaseDate(this.now()) });
      await this.write(trx, k.next, next.privateKey, null);
      return true;
    });

    this.logging.info(
      promoted
        ? `Signing keys: now signing with the new ${purpose} key`
        : `Signing keys: new ${purpose} key already promoted`,
    );
  }

  private async startRotation(purpose: SigningKeyPurpose): Promise<void> {
    const { active, next } = this.getState(purpose);
    if (!active || next) {
      return;
    }

    const bits = modulusLength(active);
    if (bits >= MIN_MODULUS_LENGTH) {
      return;
    }

    const { privateKey } = await this.generateKeypair();
    const started = await this.write(this.knex, settingKeys(purpose).next, null, privateKey);
    this.logging.info(
      started
        ? `Signing keys: published a new ${purpose} key to replace the ${bits}-bit key`
        : `Signing keys: a new ${purpose} key is already published`,
    );
  }
}
