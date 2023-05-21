import { UnauthorizedClient } from '../../helpers/errors.js';
import template from '../../helpers/template.js';

export default function checkClientGrantType({ oidc: { route, client } }, next) {
  let grantType;
  switch (route) {
    case 'device_authorization':
      grantType = 'urn:ietf:params:oauth:grant-type:device_code';
      break;
    case 'backchannel_authentication':
      grantType = 'urn:openid:params:grant-type:ciba';
      break;
    default:
      throw new Error('not implemented');
  }

  if (!client.grantTypeAllowed(grantType)) {
    throw new UnauthorizedClient(template`${grantType} is not allowed for this client`, undefined, '002');
  }

  return next();
}
