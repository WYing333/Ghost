import logging from '@tryghost/logging';
import * as errors from '@tryghost/errors';
import type { JobsService } from '../jobs-service/jobs-service';
import CheckSigningKeysJob from './check-signing-keys-job';
import { SigningKeyService } from './signing-key-service';

export type { SigningKeyProvider, SigningKeyPurpose } from './signing-key-service';

let service: SigningKeyService | undefined;
let scheduled = false;

// Runs after settings init so the key rows exist; advances any rotation that's due before
// anything signs or publishes a key.
export async function init(): Promise<void> {
  if (service) {
    return;
  }

  const { knex } = require('../../data/db');
  const instance = new SigningKeyService({ knex, logging });
  await instance.check();
  service = instance;
}

export function getInstance(): SigningKeyService {
  if (!service) {
    throw new errors.IncorrectUsageError({
      message: 'Signing keys used before init(). Call init() from boot first.',
    });
  }
  return service;
}

export async function scheduleCheckJob(jobsService: JobsService): Promise<void> {
  if (scheduled || process.env.NODE_ENV?.startsWith('test')) {
    return;
  }

  // Nothing to advance until a later boot finds a key to rotate
  if (!getInstance().isRotating()) {
    return;
  }

  // Random minute so a fleet of sites doesn't check at once
  const cron = `${Math.floor(Math.random() * 60)} ${Math.floor(Math.random() * 60)} * * * *`;
  logging.info(`[Background Job] check-signing-keys scheduled at ${cron}`);
  await jobsService.scheduleRecurring(new CheckSigningKeysJob(), { cron });
  scheduled = true;
}
