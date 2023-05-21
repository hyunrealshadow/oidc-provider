import { InvalidTarget } from '../../helpers/errors.js';

export default (superclass) => class extends superclass {
  setAudience(audience) {
    if (Array.isArray(audience)) {
      if (audience.length === 0) {
        return;
      }
      if (audience.length > 1) {
        throw new InvalidTarget('only a single audience value is supported', undefined, '005');
      }

      // eslint-disable-next-line no-param-reassign
      [audience] = audience;
    } else if (typeof audience !== 'string' || !audience) {
      throw new InvalidTarget(undefined, undefined, '002');
    }

    this.aud = audience;
  }
};
