import { InvalidRequest } from './errors.js';

export default function validatePresence(ctx, ...required) {
  const { params } = ctx.oidc;
  const missing = required.map((param) => {
    if (params[param] === undefined) {
      return param;
    }

    return undefined;
  }).filter(Boolean);

  if (missing.length) {
    throw new InvalidRequest(undefined, undefined, '062', [missing]);
  }
}
