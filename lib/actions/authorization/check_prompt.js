import { InvalidRequest } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 *
 * @throws: invalid_request
 */
export default function checkPrompt(ctx, next) {
  if (ctx.oidc.params.prompt !== undefined) {
    const { prompts } = ctx.oidc;
    const supported = instance(ctx.oidc.provider).configuration('prompts');

    for (const prompt of prompts) {
      if (!supported.has(prompt)) {
        throw new InvalidRequest(undefined, undefined, '021');
      }
    }

    if (prompts.has('none') && prompts.size !== 1) {
      throw new InvalidRequest(undefined, undefined, '022');
    }
  }

  return next();
}
