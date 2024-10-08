import instance from '../../helpers/weak_cache.js';
import {
  UnsupportedResponseType,
  UnauthorizedClient,
} from '../../helpers/errors.js';

/*
 * Validates requested response_type is supported by the provided and allowed in the client
 * configuration
 *
 * @throws: unsupported_response_type
 * @throws: unauthorized_client
 */
export default function checkResponseType(ctx, next) {
  const { params } = ctx.oidc;
  const supported = instance(ctx.oidc.provider).configuration('responseTypes');

  params.response_type = [...new Set(params.response_type.split(' '))].sort().join(' ');

  if (!supported.includes(params.response_type)) {
    throw new UnsupportedResponseType(true, undefined, '001');
  }

  if (!ctx.oidc.client.responseTypeAllowed(params.response_type)) {
    throw new UnauthorizedClient(true, undefined, '003');
  }

  return next();
}
