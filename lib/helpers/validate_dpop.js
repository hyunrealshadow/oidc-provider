import { createHash } from 'node:crypto';

import {
  jwtVerify,
  EmbeddedJWK,
  calculateJwkThumbprint,
} from 'jose';

import { InvalidDpopProof, UseDpopNonce } from './errors.js';
import instance from './weak_cache.js';
import * as base64url from './base64url.js';
import epochTime from './epoch_time.js';

const weakMap = new WeakMap();
export default async (ctx, accessToken) => {
  if (weakMap.has(ctx)) {
    return weakMap.get(ctx);
  }

  const {
    features: { dPoP: dPoPConfig },
    dPoPSigningAlgValues,
  } = instance(ctx.oidc.provider).configuration();

  if (!dPoPConfig.enabled) {
    return undefined;
  }

  const proof = ctx.get('DPoP');

  if (!proof) {
    return undefined;
  }

  const { DPoPNonces } = instance(ctx.oidc.provider);

  const requireNonce = dPoPConfig.requireNonce(ctx);
  if (typeof requireNonce !== 'boolean') {
    throw new Error('features.dPoP.requireNonce must return a boolean');
  }

  if (DPoPNonces) {
    ctx.set('DPoP-Nonce', DPoPNonces.nextNonce());
  } else if (requireNonce) {
    throw new Error('features.dPoP.nonceSecret configuration is missing');
  }

  let payload;
  let protectedHeader;
  try {
    ({ protectedHeader, payload } = await jwtVerify(proof, EmbeddedJWK, { algorithms: dPoPSigningAlgValues, typ: 'dpop+jwt' }));

    if (typeof payload.iat !== 'number' || !payload.iat) {
      throw new InvalidDpopProof(true, undefined, '001');
    }

    if (typeof payload.jti !== 'string' || !payload.jti) {
      throw new InvalidDpopProof(true, undefined, '002');
    }

    if (payload.nonce !== undefined && typeof payload.nonce !== 'string') {
      throw new InvalidDpopProof(true, undefined, '003');
    }

    if (!payload.nonce) {
      const now = epochTime();
      const diff = Math.abs(now - payload.iat);
      if (diff > 300) {
        throw new InvalidDpopProof(true, undefined, '004');
      }
    }

    if (payload.htm !== ctx.method) {
      throw new InvalidDpopProof(true, undefined, '005');
    }

    {
      const expected = new URL(ctx.oidc.urlFor(ctx.oidc.route)).href;
      let actual;
      try {
        actual = new URL(payload.htu);
        actual.hash = '';
        actual.search = '';
      } catch {}

      if (actual?.href !== expected) {
        throw new InvalidDpopProof(true, undefined, '006');
      }
    }

    if (accessToken) {
      const ath = base64url.encode(createHash('sha256').update(accessToken).digest());
      if (payload.ath !== ath) {
        throw new InvalidDpopProof(true, undefined, '007');
      }
    }
  } catch (err) {
    if (err instanceof InvalidDpopProof) {
      throw err;
    }
    throw new InvalidDpopProof(true, err.message, '008');
  }

  if (!payload.nonce && requireNonce) {
    throw new UseDpopNonce(true, undefined, '001');
  }

  if (payload.nonce && (!DPoPNonces || !DPoPNonces.checkNonce(payload.nonce))) {
    throw new UseDpopNonce(true, undefined, '002');
  }

  const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

  const result = { thumbprint, jti: payload.jti, iat: payload.iat };
  weakMap.set(ctx, result);

  return result;
};
