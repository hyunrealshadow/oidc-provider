import { InvalidGrant } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import checkPKCE from '../../helpers/pkce.js';
import revoke from '../../helpers/revoke.js';
import filterClaims from '../../helpers/filter_claims.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import resolveResource from '../../helpers/resolve_resource.js';
import epochTime from '../../helpers/epoch_time.js';

const gty = 'authorization_code';

export const handler = async function authorizationCodeHandler(ctx, next) {
  const {
    issueRefreshToken,
    allowOmittingSingleRegisteredRedirectUri,
    conformIdTokenClaims,
    features: {
      userinfo,
      mTLS: { getCertificate },
      resourceIndicators,
    },
  } = instance(ctx.oidc.provider).configuration();

  if (allowOmittingSingleRegisteredRedirectUri && ctx.oidc.params.redirect_uri === undefined) {
    // It is permitted to omit the redirect_uri if only ONE is registered on the client
    const { 0: uri, length } = ctx.oidc.client.redirectUris;
    if (uri && length === 1) {
      ctx.oidc.params.redirect_uri = uri;
    }
  }

  presence(ctx, 'code', 'redirect_uri');

  const dPoP = await dpopValidate(ctx);

  const code = await ctx.oidc.provider.AuthorizationCode.find(ctx.oidc.params.code, {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('001');
  }

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('002');
  }

  if (code.isExpired) {
    throw new InvalidGrant('003');
  }

  const grant = await ctx.oidc.provider.Grant.find(code.grantId, {
    ignoreExpiration: true,
  });

  if (!grant) {
    throw new InvalidGrant('004');
  }

  if (grant.isExpired) {
    throw new InvalidGrant('005');
  }

  checkPKCE(ctx.oidc.params.code_verifier, code.codeChallenge, code.codeChallengeMethod);

  let cert;
  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('006');
    }
  }

  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('007');
  }

  if (grant.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('002');
  }

  if (code.redirectUri !== ctx.oidc.params.redirect_uri) {
    throw new InvalidGrant('009');
  }

  if (code.consumed) {
    await revoke(ctx, code.grantId);
    throw new InvalidGrant('010');
  }

  await code.consume();

  ctx.oidc.entity('AuthorizationCode', code);
  ctx.oidc.entity('Grant', grant);

  const account = await ctx.oidc.provider.Account.findAccount(ctx, code.accountId, code);

  if (!account) {
    throw new InvalidGrant('011');
  }

  if (code.accountId !== grant.accountId) {
    throw new InvalidGrant('012');
  }

  ctx.oidc.entity('Account', account);

  const {
    AccessToken, IdToken, RefreshToken, ReplayDetection,
  } = ctx.oidc.provider;

  const at = new AccessToken({
    accountId: account.accountId,
    client: ctx.oidc.client,
    expiresWithSession: code.expiresWithSession,
    grantId: code.grantId,
    gty,
    sessionUid: code.sessionUid,
    sid: code.sid,
  });

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    at.setThumbprint('x5t', cert);
  }

  if (code.dpopJkt && !dPoP) {
    throw new InvalidGrant('013');
  }

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      ctx.oidc.client.clientId,
      dPoP.jti,
      epochTime() + 300,
    );

    ctx.assert(unique, new InvalidGrant('014'));

    if (code.dpopJkt && code.dpopJkt !== dPoP.thumbprint) {
      throw new InvalidGrant('015');
    }

    at.setThumbprint('jkt', dPoP.thumbprint);
  }

  const resource = await resolveResource(ctx, code, { userinfo, resourceIndicators });

  if (resource) {
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, ctx.oidc.client);
    at.resourceServer = new ctx.oidc.provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(resource, code.scopes);
  } else {
    at.claims = code.claims;
    at.scope = grant.getOIDCScopeFiltered(code.scopes);
  }

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  let refreshToken;
  if (await issueRefreshToken(ctx, ctx.oidc.client, code)) {
    const rt = new RefreshToken({
      accountId: account.accountId,
      acr: code.acr,
      amr: code.amr,
      authTime: code.authTime,
      claims: code.claims,
      client: ctx.oidc.client,
      expiresWithSession: code.expiresWithSession,
      grantId: code.grantId,
      gty,
      nonce: code.nonce,
      resource: code.resource,
      rotations: 0,
      scope: code.scope,
      sessionUid: code.sessionUid,
      sid: code.sid,
    });

    if (ctx.oidc.client.clientAuthMethod === 'none') {
      if (at.jkt) {
        rt.jkt = at.jkt;
      }

      if (at['x5t#S256']) {
        rt['x5t#S256'] = at['x5t#S256'];
      }
    }

    ctx.oidc.entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }

  let idToken;
  if (code.scopes.has('openid')) {
    const claims = filterClaims(code.claims, 'id_token', grant);
    const rejected = grant.getRejectedOIDCClaims();
    const token = new IdToken({
      ...await account.claims('id_token', code.scope, claims, rejected),
      acr: code.acr,
      amr: code.amr,
      auth_time: code.authTime,
    }, { ctx });

    if (conformIdTokenClaims && userinfo.enabled && !at.aud) {
      token.scope = 'openid';
    } else {
      token.scope = grant.getOIDCScopeFiltered(code.scopes);
    }

    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', code.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', code.sid);

    idToken = await token.issue({ use: 'idtoken' });
  }

  ctx.body = {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: at.scope,
    token_type: at.tokenType,
  };

  await next();
};

export const parameters = new Set(['code', 'code_verifier', 'redirect_uri']);
