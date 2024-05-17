import { InvalidRequest } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import isPlainObject from '../../helpers/_/is_plain_object.js';

/*
 * If claims parameter is provided and supported handles its validation
 * - should not be combined with rt none
 * - should be JSON serialized object with id_token or userinfo properties as objects
 * - claims.userinfo should not be used if authorization result is not access_token
 *
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 *
 * @throws: invalid_request
 */
export default function checkClaims(ctx, next) {
  const { params } = ctx.oidc;

  if (params.claims !== undefined) {
    const { features: { claimsParameter, userinfo } } = instance(ctx.oidc.provider).configuration();

    if (claimsParameter.enabled) {
      if (params.response_type === 'none') {
        throw new InvalidRequest(undefined, undefined, '001');
      }

      let claims;

      try {
        claims = JSON.parse(params.claims);
      } catch (err) {
        throw new InvalidRequest(undefined, undefined, '002');
      }

      if (!isPlainObject(claims)) {
        throw new InvalidRequest(undefined, undefined, '003');
      }

      if (claims.userinfo === undefined && claims.id_token === undefined) {
        throw new InvalidRequest(undefined, undefined, '004');
      }

      if (claims.userinfo !== undefined && !isPlainObject(claims.userinfo)) {
        throw new InvalidRequest(undefined, undefined, '005');
      }

      if (claims.id_token !== undefined && !isPlainObject(claims.id_token)) {
        throw new InvalidRequest(undefined, undefined, '006');
      }

      if (claims.userinfo && !userinfo.enabled) {
        throw new InvalidRequest(undefined, undefined, '007');
      }

      if (params.response_type === 'id_token' && claims.userinfo) {
        throw new InvalidRequest(undefined, undefined, '008');
      }
    }
  }

  return next();
}
