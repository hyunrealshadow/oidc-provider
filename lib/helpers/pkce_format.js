import { InvalidRequest } from './errors.js';

const check = /[^\w.\-~]/;

export default (input, param) => {
  if (input.length < 43) {
    throw new InvalidRequest(undefined, undefined, '059', [param]);
  }

  if (input.length > 128) {
    throw new InvalidRequest(undefined, undefined, '060', [param]);
  }

  if (check.test(input)) {
    throw new InvalidRequest(undefined, undefined, '061', [param]);
  }
};
