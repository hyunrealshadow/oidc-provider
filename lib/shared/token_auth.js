import { InvalidRequest, InvalidClientAuth } from '../helpers/errors.js';
import setWWWAuthenticate from '../helpers/set_www_authenticate.js';
import * as JWT from '../helpers/jwt.js';
import instance from '../helpers/weak_cache.js';
import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import { noVSCHAR } from '../consts/client_attributes.js';

import rejectDupes from './reject_dupes.js';
import getJWTAuthMiddleware from './token_jwt_auth.js';

const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// see https://tools.ietf.org/html/rfc6749#appendix-B
function decodeAuthToken(token) {
  // TODO: in v9.x consider enabling stricter encoding check
  // if (token.match(/[^a-zA-Z0-9%+]/)) {
  //   throw new Error();
  // }
  const authToken = decodeURIComponent(token.replace(/\+/g, '%20'));
  if (noVSCHAR.test(authToken)) {
    throw new Error('invalid character found');
  }
  return authToken;
}

export default function tokenAuth(provider) {
  const tokenJwtAuth = getJWTAuthMiddleware(provider);
  const authParams = new Set(['client_id']);

  instance(provider).configuration('clientAuthMethods').forEach((method) => {
    switch (method) {
      case 'client_secret_post':
        authParams.add('client_secret');
        break;
      case 'client_secret_jwt':
      case 'private_key_jwt':
        authParams.add('client_assertion');
        authParams.add('client_assertion_type');
        break;
      default:
    }
  });

  authParams.forEach(Set.prototype.add.bind(instance(provider).grantTypeParams.get(undefined)));

  return {
    params: authParams,
    middleware: [
      rejectDupes.bind(undefined, { only: authParams }),
      async function setWWWAuthenticateHeader(ctx, next) {
        try {
          await next();
        } catch (err) {
          if (err.statusCode === 401 && ctx.header.authorization !== undefined) {
            setWWWAuthenticate(ctx, 'Basic', {
              realm: provider.issuer,
              error: err.message,
              error_description: err.error_description,
            });
          }
          throw err;
        }
      },
      async function findClientId(ctx, next) {
        const {
          params: {
            client_id: clientId,
            client_assertion: clientAssertion,
            client_assertion_type: clientAssertionType,
            client_secret: clientSecret,
          },
        } = ctx.oidc;

        if (ctx.headers.authorization !== undefined) {
          const parts = ctx.headers.authorization.split(' ');
          if (parts.length !== 2 || parts[0].toLowerCase() !== 'basic') {
            throw new InvalidRequest(undefined, undefined, '054');
          }

          const basic = Buffer.from(parts[1], 'base64').toString('utf8');
          const i = basic.indexOf(':');

          if (i === -1) {
            throw new InvalidRequest(undefined, undefined, '054');
          }

          try {
            ctx.oidc.authorization.clientId = decodeAuthToken(basic.slice(0, i));
            ctx.oidc.authorization.clientSecret = decodeAuthToken(basic.slice(i + 1));
          } catch (err) {
            throw new InvalidRequest(undefined, undefined, '072');
          }

          if (clientId !== undefined && ctx.oidc.authorization.clientId !== clientId) {
            throw new InvalidRequest(undefined, undefined, '073');
          }

          if (!ctx.oidc.authorization.clientSecret) {
            throw new InvalidRequest(undefined, undefined, '074');
          }

          if (clientSecret !== undefined) {
            throw new InvalidRequest(undefined, undefined, '075');
          }

          ctx.oidc.authorization.methods = ['client_secret_basic', 'client_secret_post'];
        } else if (clientId !== undefined) {
          ctx.oidc.authorization.clientId = clientId;
          ctx.oidc.authorization.methods = clientSecret
            ? ['client_secret_basic', 'client_secret_post']
            : ['none', 'tls_client_auth', 'self_signed_tls_client_auth'];
        }

        if (clientAssertion !== undefined) {
          if (clientSecret !== undefined || ctx.headers.authorization !== undefined) {
            throw new InvalidRequest(undefined, undefined, '075');
          }

          let sub;
          try {
            ({ payload: { sub } } = JWT.decode(clientAssertion));
          } catch (err) {
            throw new InvalidRequest(undefined, undefined, '077');
          }

          if (!sub) {
            throw new InvalidClientAuth('001');
          }

          if (clientId && sub !== clientId) {
            throw new InvalidRequest(undefined, undefined, '078');
          }

          if (clientAssertionType === undefined) {
            throw new InvalidRequest(undefined, undefined, '079');
          }

          if (clientAssertionType !== assertionType) {
            throw new InvalidRequest(undefined, undefined, '080', [assertionType]);
          }

          ctx.oidc.authorization.clientId = sub;
          ctx.oidc.authorization.methods = ['client_secret_jwt', 'private_key_jwt'];
        }

        if (!ctx.oidc.authorization.clientId) {
          throw new InvalidRequest(undefined, undefined, '081');
        }

        return next();
      },
      async function loadClient(ctx, next) {
        const client = await provider.Client.find(ctx.oidc.authorization.clientId);

        if (!client) {
          throw new InvalidClientAuth('002');
        }

        ctx.oidc.entity('Client', client);

        await next();
      },
      async function auth(ctx, next) {
        const {
          params,
          client: {
            clientAuthMethod,
            clientAuthSigningAlg,
          },
          authorization: {
            methods,
            clientSecret,
          },
        } = ctx.oidc;

        if (!methods.includes(clientAuthMethod)) {
          throw new InvalidClientAuth('003');
        }

        switch (clientAuthMethod) { // eslint-disable-line default-case
          case 'none':
            break;

          case 'client_secret_basic':
          case 'client_secret_post': {
            ctx.oidc.client.checkClientSecretExpiration('could not authenticate the client - its client secret is expired');
            const actual = params.client_secret || clientSecret;
            const matches = await ctx.oidc.client.compareClientSecret(actual);
            if (!matches) {
              throw new InvalidClientAuth('004');
            }

            break;
          }

          case 'client_secret_jwt':
            ctx.oidc.client.checkClientSecretExpiration('could not authenticate the client - its client secret used for the client_assertion is expired');
            await tokenJwtAuth(
              ctx,
              ctx.oidc.client.symmetricKeyStore,
              clientAuthSigningAlg ? [clientAuthSigningAlg] : instance(provider).configuration('clientAuthSigningAlgValues').filter((alg) => alg.startsWith('HS')),
            );

            break;

          case 'private_key_jwt':
            await tokenJwtAuth(
              ctx,
              ctx.oidc.client.asymmetricKeyStore,
              clientAuthSigningAlg ? [clientAuthSigningAlg] : instance(provider).configuration('clientAuthSigningAlgValues').filter((alg) => !alg.startsWith('HS')),
            );

            break;

          case 'tls_client_auth': {
            const { mTLS: { getCertificate, certificateAuthorized, certificateSubjectMatches } } = instance(provider).configuration('features');

            const cert = getCertificate(ctx);

            if (!cert) {
              throw new InvalidClientAuth('005');
            }

            if (!certificateAuthorized(ctx)) {
              throw new InvalidClientAuth('006');
            }

            for (const [prop, key] of Object.entries({
              tlsClientAuthSubjectDn: 'tls_client_auth_subject_dn',
              tlsClientAuthSanDns: 'tls_client_auth_san_dns',
              tlsClientAuthSanIp: 'tls_client_auth_san_ip',
              tlsClientAuthSanEmail: 'tls_client_auth_san_email',
              tlsClientAuthSanUri: 'tls_client_auth_san_uri',
            })) {
              const value = ctx.oidc.client[prop];
              if (value) {
                if (!certificateSubjectMatches(ctx, key, value)) {
                  throw new InvalidClientAuth('007');
                }
                break;
              }
            }

            break;
          }
          case 'self_signed_tls_client_auth': {
            const { mTLS: { getCertificate } } = instance(provider).configuration('features');
            const cert = getCertificate(ctx);

            if (!cert) {
              throw new InvalidClientAuth('008');
            }

            await ctx.oidc.client.asymmetricKeyStore.refresh();
            const expected = certificateThumbprint(cert);
            const match = [...ctx.oidc.client.asymmetricKeyStore].find(({ 'x5t#S256': actual }) => actual === expected);

            if (!match) {
              throw new InvalidClientAuth('009');
            }

            break;
          }
        }

        await next();
      },
    ],
  };
}
