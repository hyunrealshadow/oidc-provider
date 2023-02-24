import * as url from 'node:url';
import * as querystring from 'node:querystring';

export default function redirectUri(uri, payload, mode) {
  const parsed = url.parse(uri, true);
  const normalisePayload = {};
  Object.keys(payload).forEach((key) => {
    const value = payload[key];
    if (value instanceof String) {
      // eslint-disable-next-line no-param-reassign
      normalisePayload[key] = value.toString();
    } else {
      normalisePayload[key] = value;
    }
  });

  parsed.search = null;

  // handles a case where url module adds unintended / to the pathname
  // i.e. http://www.example.com => http://www.example.com/
  if (parsed.pathname === '/' && !uri.endsWith('/')) parsed.pathname = null;

  switch (mode) {
    case 'fragment':
      parsed.hash = querystring.stringify(normalisePayload);
      break;
    default:
      Object.assign(parsed.query, normalisePayload);
      break;
  }

  return url.format(parsed);
}
