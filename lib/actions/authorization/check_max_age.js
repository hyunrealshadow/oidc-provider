import { InvalidRequest } from '../../helpers/errors.js';

/*
 * Validates the max_age parameter and handles max_age=0 to prompt=login translation
 *
 * @throws: invalid_request
 */
export default function checkMaxAge(ctx, next) {
  if (ctx.oidc.params.max_age !== undefined) {
    const maxAge = +ctx.oidc.params.max_age;

    if (!Number.isSafeInteger(maxAge) || Math.sign(maxAge) === -1) {
      throw new InvalidRequest(undefined, undefined, '012');
    }

    if (maxAge === 0) {
      const { prompts } = ctx.oidc;
      ctx.oidc.params.max_age = undefined;
      if (!prompts.has('login')) {
        prompts.add('login');
        ctx.oidc.params.prompt = [...prompts].join(' ');
      }
    }
  }

  return next();
}
