import { InvalidRequest } from './errors.js';
import template from './template.js';

const check = /[^\w.\-~]/;

export default (input, param) => {
  if (input.length < 43) {
    throw new InvalidRequest(template`${param} must be a string with a minimum length of 43 characters`, undefined, undefined, '059');
  }

  if (input.length > 128) {
    throw new InvalidRequest(template`${param} must be a string with a maximum length of 128 characters`, undefined, undefined, '060');
  }

  if (check.test(input)) {
    throw new InvalidRequest(template`${param} contains invalid characters`, undefined, undefined, '061');
  }
};
