import { InvalidRequest, UnsupportedResponseMode } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import { isFrontChannel } from '../../helpers/resolve_response_mode.js';
import template from '../../helpers/template.js';

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 *
 * @throws: invalid_request
 */
export default function checkResponseMode(ctx, next, forceCheck) {
  const { params, client } = ctx.oidc;

  const frontChannel = isFrontChannel(params.response_type);

  const mode = ctx.oidc.responseMode;

  if (
    mode !== undefined
    && !instance(ctx.oidc.provider).responseModes.has(mode)
  ) {
    params.response_mode = undefined;
    throw new UnsupportedResponseMode();
  }

  const JWT = /jwt/.test(mode);

  if (
    mode !== undefined && JWT
    && (
      /^HS/.test(client.authorizationSignedResponseAlg)
      || /^(A|dir$)/.test(client.authorizationEncryptedResponseAlg)
    )
  ) {
    try {
      client.checkClientSecretExpiration('client secret is expired, cannot issue a JWT Authorization response');
    } catch (err) {
      const [explicit] = mode === 'jwt' ? [undefined] : mode.split('.');
      params.response_mode = explicit || undefined;
      throw err;
    }
  }

  if (mode === 'query' && frontChannel) {
    throw new InvalidRequest('response_mode not allowed for this response_type', undefined, undefined, '024');
  } else if (mode === 'query.jwt' && frontChannel && !client.authorizationEncryptedResponseAlg) {
    throw new InvalidRequest('response_mode not allowed for this response_type unless encrypted', undefined, undefined, '025');
  }

  const fapiProfile = ctx.oidc.isFapi('1.0 Final', '1.0 ID2');
  if (params.response_type && fapiProfile) {
    if (((!params.request && !params.request_uri) || forceCheck) && !params.response_type.includes('id_token') && !JWT) {
      throw new InvalidRequest(template`requested response_mode not allowed for the requested response_type in FAPI ${fapiProfile}`, undefined, undefined, '026');
    }
  }

  return next();
}
