import crypto from 'node:crypto';
import { getPublicKeyInfo } from '../../core/server/lib/public-jwk';
import type { SigningKeyProvider } from '../../core/server/services/signing-keys/signing-key-service';

/** A SigningKeyProvider for fixed keys; the first signs, all verify. */
export function staticSigningKeys(...privateKeys: string[]): SigningKeyProvider {
  return {
    async getSigningKey() {
      return { privateKey: privateKeys[0], kid: (await getPublicKeyInfo(privateKeys[0])).kid };
    },
    async getVerificationKeys() {
      return Promise.all(
        privateKeys.map(async (pem) => ({
          ...(await getPublicKeyInfo(pem)),
          publicKey: crypto
            .createPublicKey(pem)
            .export({ type: 'pkcs1', format: 'pem' })
            .toString(),
        })),
      );
    },
  };
}
