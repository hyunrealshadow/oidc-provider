import { InvalidRequest } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import checkFormat from '../../helpers/pkce_format.js';

/*
 * - assign default code_challenge_method if a code_challenge is provided
 * - check presence of code code_challenge if code_challenge_method is provided
 * - enforce PKCE use for native clients using hybrid or code flow
 */
export default function checkPKCE(ctx, next) {
  const { params, route } = ctx.oidc;
  const { pkce } = instance(ctx.oidc.provider).configuration();

  if (!params.code_challenge_method && params.code_challenge) {
    if (pkce.methods.includes('plain')) {
      params.code_challenge_method = 'plain';
    } else {
      throw new InvalidRequest(undefined, undefined, '017');
    }
  }

  if (params.code_challenge_method) {
    if (!pkce.methods.includes(params.code_challenge_method)) {
      throw new InvalidRequest(undefined, undefined, '018');
    }

    if (!params.code_challenge) {
      throw new InvalidRequest(undefined, undefined, '019');
    }
  }

  if (params.response_type.includes('code')) {
    if (
      !params.code_challenge
      && (
        pkce.required(ctx, ctx.oidc.client)
        || (ctx.oidc.isFapi('1.0 Final') && route === 'pushed_authorization_request')
      )) {
      throw new InvalidRequest(undefined, undefined, '020');
    }
  }

  if (params.code_challenge !== undefined) {
    checkFormat(params.code_challenge, 'code_challenge');
  }

  return next();
}
