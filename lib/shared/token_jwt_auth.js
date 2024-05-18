import { InvalidClientAuth } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import * as JWT from '../helpers/jwt.js';

export default function getTokenJwtAuth(provider) {
  const clockTolerance = instance(provider).configuration('clockTolerance');
  return async function tokenJwtAuth(
    ctx,
    keystore,
    algorithms,
  ) {
    const acceptedAud = ctx.oidc.clientJwtAuthExpectedAudience();
    const { header, payload } = JWT.decode(ctx.oidc.params.client_assertion);

    if (!algorithms.includes(header.alg)) {
      throw new InvalidClientAuth('010');
    }

    if (!payload.exp) {
      throw new InvalidClientAuth('011');
    }

    if (!payload.jti) {
      throw new InvalidClientAuth('012');
    }

    if (!payload.iss) {
      throw new InvalidClientAuth('013');
    }

    if (payload.iss !== ctx.oidc.client.clientId) {
      throw new InvalidClientAuth('014');
    }

    if (!payload.aud) {
      throw new InvalidClientAuth('015');
    }

    if (Array.isArray(payload.aud)) {
      if (!payload.aud.some((aud) => acceptedAud.has(aud))) {
        throw new InvalidClientAuth('016');
      }
    } else if (!acceptedAud.has(payload.aud)) {
      throw new InvalidClientAuth('017');
    }

    try {
      await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
        clockTolerance,
        ignoreAzp: true,
      });
    } catch (err) {
      const e = new InvalidClientAuth('099');
      e.error_detail = err.message;
      throw e;
    }

    const unique = await provider.ReplayDetection.unique(
      payload.iss,
      payload.jti,
      payload.exp + clockTolerance,
    );

    if (!unique) {
      throw new InvalidClientAuth('018');
    }
  };
}
