import { InvalidRequest } from '../helpers/errors.js';

function exceptMap([key, value]) {
  if (Array.isArray(value) && !this.has(key)) {
    return key;
  }
  return undefined;
}

function onlyMap([key, value]) {
  if (Array.isArray(value) && this.has(key)) {
    return key;
  }
  return undefined;
}

function defaultMap([key, value]) {
  return Array.isArray(value) ? key : undefined;
}

// eslint-disable-next-line default-param-last
export default function rejectDupes({ except, only } = {}, ctx, next) {
  let mapFn;

  if (except) {
    mapFn = exceptMap.bind(except);
  } else if (only) {
    mapFn = onlyMap.bind(only);
  } else {
    mapFn = defaultMap;
  }

  const dupes = Object.entries(ctx.oidc.params).map(mapFn);

  if (dupes.some(Boolean)) {
    const params = dupes.filter(Boolean);
    params.forEach((param) => {
      ctx.oidc.params[param] = undefined;
    });
    throw new InvalidRequest(undefined, undefined, '066', [params]);
  }

  return next();
}
