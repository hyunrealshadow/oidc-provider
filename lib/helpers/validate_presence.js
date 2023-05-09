import { InvalidRequest } from './errors.js';
import template from './template.js';

export default function validatePresence(ctx, ...required) {
  const { params } = ctx.oidc;
  const missing = required.map((param) => {
    if (params[param] === undefined) {
      return param;
    }

    return undefined;
  }).filter(Boolean);

  if (missing.length) {
    throw new InvalidRequest(template`missing required ${[['parameter', 'parameters', missing.length], { type: 'pluralize' }]} ${[missing, { type: 'conjunction' }]}`, undefined, undefined, '062');
  }
}
