import omitBy from '../helpers/_/omit_by.js';
import constantEquals from '../helpers/constant_equals.js';
import noCache from '../shared/no_cache.js';
import { json as parseBody } from '../shared/selective_body.js';
import epochTime from '../helpers/epoch_time.js';
import { InvalidToken, InvalidRequest } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import setWWWAuthenticate from '../helpers/set_www_authenticate.js';

const FORBIDDEN = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret_expires_at',
  'client_id_issued_at',
];

async function setWWWAuthenticateHeader(ctx, next) {
  try {
    await next();
  } catch (err) {
    if (err.expose) {
      setWWWAuthenticate(ctx, 'Bearer', {
        realm: ctx.oidc.issuer,
        ...(err.error_description !== 'no access token provided' ? {
          error: err.message,
          error_description: err.error_description,
        } : undefined),
      });
    }
    throw err;
  }
}

const validateRegistrationAccessToken = [
  setWWWAuthenticateHeader,
  async function validateRegistrationAccessToken(ctx, next) {
    const regAccessToken = await ctx.oidc.provider.RegistrationAccessToken.find(
      ctx.oidc.getAccessToken(),
    );
    ctx.assert(regAccessToken, new InvalidToken('001'));

    const client = await ctx.oidc.provider.Client.find(ctx.params.clientId);

    if (!client || client.clientId !== regAccessToken.clientId) {
      await regAccessToken.destroy();
      throw new InvalidToken('002');
    }

    ctx.oidc.entity('Client', client);
    ctx.oidc.entity('RegistrationAccessToken', regAccessToken);

    await next();
  },
];

export const post = [
  noCache,
  setWWWAuthenticateHeader,
  parseBody,
  async function validateInitialAccessToken(ctx, next) {
    const { oidc: { provider } } = ctx;
    const { initialAccessToken } = instance(provider).configuration('features.registration');
    switch (initialAccessToken && typeof initialAccessToken) {
      case 'boolean': {
        const iat = await provider.InitialAccessToken.find(ctx.oidc.getAccessToken());
        ctx.assert(iat, new InvalidToken('003'));
        ctx.oidc.entity('InitialAccessToken', iat);
        break;
      }
      case 'string': {
        const valid = constantEquals(
          initialAccessToken,
          ctx.oidc.getAccessToken(),
          1000,
        );
        ctx.assert(valid, new InvalidToken('004'));
        break;
      }
      default:
    }

    await next();
  },
  async function registrationResponse(ctx, next) {
    const { oidc: { provider } } = ctx;
    const { idFactory, secretFactory, issueRegistrationAccessToken } = instance(provider).configuration('features.registration');
    const properties = {};
    const clientId = idFactory(ctx);

    let rat;

    if (
      issueRegistrationAccessToken === true
      || (typeof issueRegistrationAccessToken === 'function' && issueRegistrationAccessToken(ctx))
    ) {
      rat = new provider.RegistrationAccessToken({ clientId });
      ctx.oidc.entity('RegistrationAccessToken', rat);
    }

    Object.assign(properties, ctx.oidc.body, {
      client_id: clientId,
      client_id_issued_at: epochTime(),
    });

    const { Client } = provider;
    const secretRequired = Client.needsSecret(properties);

    if (secretRequired) {
      Object.assign(properties, {
        client_secret: await secretFactory(ctx),
        client_secret_expires_at: 0,
      });
    } else {
      delete properties.client_secret;
      delete properties.client_secret_expires_at;
    }

    if (
      ctx.oidc.entities.InitialAccessToken?.policies
    ) {
      const { policies } = ctx.oidc.entities.InitialAccessToken;
      const implementations = instance(provider).configuration('features.registration.policies');
      for (const policy of policies) {
        await implementations[policy](ctx, properties); // eslint-disable-line no-await-in-loop
      }

      if (rat && !('policies' in rat)) {
        rat.policies = policies;
      }
    }

    const client = await instance(provider).clientAdd(properties, { store: true, ctx });
    ctx.oidc.entity('Client', client);

    ctx.body = client.metadata();

    if (rat) {
      Object.assign(ctx.body, {
        registration_client_uri: ctx.oidc.urlFor('client', {
          clientId: properties.client_id,
        }),
        registration_access_token: await rat.save(),
      });
    }

    ctx.status = 201;

    provider.emit('registration_create.success', ctx, client);

    await next();
  },
];

export const get = [
  noCache,
  ...validateRegistrationAccessToken,

  async function clientReadResponse(ctx, next) {
    if (ctx.oidc.client.noManage) {
      throw new InvalidRequest(403, undefined, '043');
    }

    ctx.body = ctx.oidc.client.metadata();

    Object.assign(ctx.body, {
      registration_access_token: ctx.oidc.getAccessToken(),
      registration_client_uri: ctx.oidc.urlFor('client', {
        clientId: ctx.params.clientId,
      }),
    });

    await next();
  },
];

export const put = [
  noCache,
  ...validateRegistrationAccessToken,
  parseBody,

  async function forbiddenFields(ctx, next) {
    const hit = FORBIDDEN.find((field) => ctx.oidc.body[field] !== undefined);
    ctx.assert(!hit, new InvalidRequest(undefined, undefined, '044', [hit]));
    await next();
  },

  async function equalChecks(ctx, next) {
    ctx.assert(ctx.oidc.body.client_id === ctx.oidc.client.clientId, new InvalidRequest(undefined, undefined, '045'));

    if ('client_secret' in ctx.oidc.body) {
      const clientSecretValid = constantEquals(
        typeof ctx.oidc.body.client_secret === 'string' ? ctx.oidc.body.client_secret : '',
        ctx.oidc.client.clientSecret || '',
        1000,
      );

      ctx.assert(clientSecretValid, new InvalidRequest(undefined, undefined, '046'));
    }

    await next();
  },

  async function clientUpdateResponse(ctx, next) {
    if (ctx.oidc.client.noManage) {
      throw new InvalidRequest(403, undefined, '047');
    }

    const properties = omitBy({
      client_id: ctx.oidc.client.clientId,
      client_id_issued_at: ctx.oidc.client.clientIdIssuedAt,
      ...ctx.oidc.body,
    }, (value) => value === null || value === '');

    const { oidc: { provider } } = ctx;
    const { secretFactory } = instance(provider).configuration('features.registration');

    const secretRequired = !ctx.oidc.client.clientSecret
      && provider.Client.needsSecret(properties);

    if (secretRequired) {
      Object.assign(properties, {
        client_secret: await secretFactory(ctx),
        client_secret_expires_at: 0,
      });
    } else {
      Object.assign(properties, {
        client_secret: ctx.oidc.client.clientSecret,
        client_secret_expires_at: ctx.oidc.client.clientSecretExpiresAt,
      });
    }

    if (ctx.oidc.entities.RegistrationAccessToken.policies) {
      const { policies } = ctx.oidc.entities.RegistrationAccessToken;
      const implementations = instance(provider).configuration('features.registration.policies');
      for (const policy of policies) {
        await implementations[policy](ctx, properties); // eslint-disable-line no-await-in-loop
      }
    }

    const client = await instance(provider).clientAdd(properties, { store: true, ctx });

    ctx.body = client.metadata();

    Object.assign(ctx.body, {
      registration_access_token: ctx.oidc.getAccessToken(),
      registration_client_uri: ctx.oidc.urlFor('client', {
        clientId: ctx.params.clientId,
      }),
    });

    const management = instance(provider).configuration('features.registrationManagement');
    if (
      management.rotateRegistrationAccessToken === true
      || (typeof management.rotateRegistrationAccessToken === 'function' && await management.rotateRegistrationAccessToken(ctx))
    ) {
      ctx.oidc.entity('RotatedRegistrationAccessToken', ctx.oidc.entities.RegistrationAccessToken);
      const rat = new provider.RegistrationAccessToken({
        client: ctx.oidc.client,
        policies: ctx.oidc.entities.RegistrationAccessToken.policies,
      });

      await ctx.oidc.registrationAccessToken.destroy();

      ctx.oidc.entity('RegistrationAccessToken', rat);
      ctx.body.registration_access_token = await rat.save();
    }

    provider.emit('registration_update.success', ctx, ctx.oidc.client);

    await next();
  },
];

export const del = [
  noCache,
  ...validateRegistrationAccessToken,

  async function clientRemoveResponse(ctx, next) {
    if (ctx.oidc.client.noManage) {
      throw new InvalidRequest(403, undefined, '048');
    }

    const { oidc: { provider } } = ctx;

    await instance(provider).clientRemove(ctx.oidc.client.clientId);
    await ctx.oidc.entities.RegistrationAccessToken.destroy();

    ctx.status = 204;

    provider.emit('registration_delete.success', ctx, ctx.oidc.client);

    await next();
  },
];
