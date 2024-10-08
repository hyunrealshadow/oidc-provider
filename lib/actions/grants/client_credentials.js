import instance from '../../helpers/weak_cache.js';
import { InvalidGrant, InvalidTarget, InvalidScope } from '../../helpers/errors.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import checkResource from '../../shared/check_resource.js';
import epochTime from '../../helpers/epoch_time.js';

export const handler = async function clientCredentialsHandler(ctx, next) {
  const { client } = ctx.oidc;
  const { ClientCredentials, ReplayDetection } = ctx.oidc.provider;
  const {
    features: {
      mTLS: { getCertificate },
    },
    scopes: statics,
  } = instance(ctx.oidc.provider).configuration();

  const dPoP = await dpopValidate(ctx);

  await checkResource(ctx, () => {});

  const scopes = ctx.oidc.params.scope ? [...new Set(ctx.oidc.params.scope.split(' '))] : [];

  if (client.scope) {
    const allowList = new Set(client.scope.split(' '));

    for (const scope of scopes.filter(Set.prototype.has.bind(statics))) {
      if (!allowList.has(scope)) {
        throw new InvalidScope(scope, undefined, '001');
      }
    }
  }

  const token = new ClientCredentials({
    client,
    scope: scopes.join(' ') || undefined,
  });

  const { 0: resourceServer, length } = Object.values(ctx.oidc.resourceServers);
  if (resourceServer) {
    if (length !== 1) {
      throw new InvalidTarget(true, undefined, '003');
    }
    token.resourceServer = resourceServer;
    token.scope = scopes.filter(Set.prototype.has.bind(new Set(resourceServer.scope.split(' ')))).join(' ') || undefined;
  }

  if (client.tlsClientCertificateBoundAccessTokens) {
    const cert = getCertificate(ctx);

    if (!cert) {
      throw new InvalidGrant('006');
    }
    token.setThumbprint('x5t', cert);
  }

  if (dPoP) {
    const unique = await ReplayDetection.unique(client.clientId, dPoP.jti, epochTime() + 300);

    ctx.assert(unique, new InvalidGrant('014'));

    token.setThumbprint('jkt', dPoP.thumbprint);
  } else if (ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('007');
  }

  ctx.oidc.entity('ClientCredentials', token);
  const value = await token.save();

  ctx.body = {
    access_token: value,
    expires_in: token.expiration,
    token_type: token.tokenType,
    scope: token.scope,
  };

  await next();
};

export const parameters = new Set(['scope']);
