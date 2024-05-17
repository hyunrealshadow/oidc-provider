import { InvalidRequest, RequestNotSupported, RequestUriNotSupported } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Rejects request and request_uri parameters when not supported.
 *
 * @throws: request_not_supported
 * @throws: request_uri_not_supported
 */
export default function rejectUnsupported(ctx, next) {
  const { requestObjects, pushedAuthorizationRequests } = instance(ctx.oidc.provider).configuration('features');
  const { params } = ctx.oidc;

  if (params.request !== undefined && !requestObjects.request) {
    throw new RequestNotSupported(undefined, undefined, '001');
  }

  if (
    params.request_uri !== undefined
    && (ctx.oidc.route !== 'authorization' || !(requestObjects.requestUri || pushedAuthorizationRequests.enabled))
  ) {
    // TODO: https://gitlab.com/openid/conformance-suite/-/issues/1139
    if (ctx.oidc.route === 'pushed_authorization_request') {
      throw new InvalidRequest(undefined, undefined, '033');
    }

    throw new RequestUriNotSupported(undefined, undefined, '001');
  }

  return next();
}
