import crypto from 'node:crypto';
import * as errors from '@tryghost/errors';

export interface PublicRsaJwk {
  kty: string;
  n: string;
  e: string;
}

export interface PublicKeyInfo {
  /** RFC 7638 thumbprint, the `kid` node-jose used to derive for the same key. */
  kid: string;
  jwk: PublicRsaJwk;
}

// Parsing a PEM and thumbprinting it costs real CPU, so results are shared
// across every consumer of the same key. Keyed by digest so the cache never
// holds another reference to private key material.
const cache = new Map<string, Promise<PublicKeyInfo>>();

async function parse(pem: string): Promise<PublicKeyInfo> {
  // jose 6 is ESM-only. tsc emits this as `require('jose')` under module: commonjs,
  // which resolves via Node's require(esm) - available on every Node in `engines`.
  const { calculateJwkThumbprint } = await import('jose');

  // Node handles private and public PEMs in PKCS#1, PKCS#8 and SPKI, and exports public fields only.
  const publicKey = crypto.createPublicKey(pem);
  const { kty, n, e } = publicKey.export({ format: 'jwk' });

  if (kty !== 'RSA' || !n || !e) {
    throw new errors.IncorrectUsageError({
      message: 'Expected an RSA key',
    });
  }

  const jwk: PublicRsaJwk = { kty, n, e };

  return { kid: await calculateJwkThumbprint(jwk, 'sha256'), jwk };
}

/**
 * Public JWK and `kid` for a PEM-encoded RSA private or public key. Never
 * returns private parameters.
 */
export function getPublicKeyInfo(pem: string): Promise<PublicKeyInfo> {
  const digest = crypto.createHash('sha256').update(pem).digest('hex');

  let info = cache.get(digest);

  if (!info) {
    info = parse(pem).catch((err) => {
      // Don't pin a failure forever - a later caller should retry.
      cache.delete(digest);
      throw err;
    });
    cache.set(digest, info);
  }

  return info;
}
