/* eslint-disable camelcase */
/* eslint-disable max-classes-per-file */

import upperFirst from './_/upper_first.js';
import camelCase from './_/camel_case.js';

export class OIDCProviderError extends Error {
  allow_redirect = true;

  constructor(status, message, errno) {
    super(message);
    this.name = this.constructor.name;
    this.message = message;
    this.errno = `OIDP${errno}`;
    this.error = message;
    this.status = status;
    this.statusCode = status;
    this.expose = status < 500;
  }
}

export class CustomOIDCProviderError extends OIDCProviderError {
  constructor(message, description, errno) {
    super(400, message, `90${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description });
  }
}

export class InvalidToken extends OIDCProviderError {
  error_description = 'invalid token provided';

  constructor(detail, errno) {
    super(401, 'invalid_token', `10${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

export class InvalidClientMetadata extends OIDCProviderError {
  constructor(description, detail, errno) {
    const message = description.startsWith('redirect_uris')
      ? 'invalid_redirect_uri' : 'invalid_client_metadata';
    super(400, message, `11${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: description,
      error_detail: detail,
    });
  }
}

export class InvalidScope extends OIDCProviderError {
  constructor(description, scope, detail, errno) {
    super(400, 'invalid_scope', `12${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      scope,
      error_description: description,
      error_detail: detail,
    });
  }
}

export class InsufficientScope extends OIDCProviderError {
  constructor(description, scope, detail, errno) {
    super(403, 'insufficient_scope', `13${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      scope,
      error_description: description,
      error_detail: detail,
    });
  }
}

export class InvalidRequest extends OIDCProviderError {
  constructor(description, code, detail, errno) {
    super(code ?? 400, 'invalid_request', `14${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: description || 'request is invalid',
      error_detail: detail,
      expose: true,
    });
  }
}

export class SessionNotFound extends InvalidRequest {
}

export class InvalidClientAuth extends OIDCProviderError {
  error_description = 'client authentication failed';

  constructor(detail, errno) {
    super(401, 'invalid_client', `15${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

export class InvalidGrant extends OIDCProviderError {
  error_description = 'grant request is invalid';

  constructor(detail, errno) {
    super(400, 'invalid_grant', `16${errno}`);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

export class InvalidRedirectUri extends OIDCProviderError {
  error_description = 'redirect_uri did not match any of the client\'s registered redirect_uris';

  allow_redirect = false;

  constructor() {
    super(400, 'invalid_redirect_uri', '17001');
    Error.captureStackTrace(this, this.constructor);
  }
}

export class WebMessageUriMismatch extends OIDCProviderError {
  error_description = 'web_message_uri did not match any client\'s registered web_message_uris';

  allow_redirect = false;

  constructor() {
    super(400, 'web_message_uri_mismatch', '18001');
    Error.captureStackTrace(this, this.constructor);
  }
}

function E(message, errorDescription, errnoType) {
  const klassName = upperFirst(camelCase(message));
  const klass = class extends OIDCProviderError {
    error_description = errorDescription;

    constructor(description, detail, errno) {
      super(400, message, `${errnoType}${errno}`);
      Error.captureStackTrace(this, this.constructor);

      if (description) {
        this.error_description = description;
      }

      if (detail) {
        this.error_detail = detail;
      }
    }
  };
  Object.defineProperty(klass, 'name', { value: klassName });
  return klass;
}

export const AccessDenied = E('access_denied', undefined, '21');
export const AuthorizationPending = E('authorization_pending', 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps', '22');
export const ConsentRequired = E('consent_required', undefined, '23');
export const ExpiredLoginHintToken = E('expired_login_hint_token', undefined, '24');
export const ExpiredToken = E('expired_token', undefined, '25');
export const InteractionRequired = E('interaction_required', undefined, '26');
export const InvalidBindingMessage = E('invalid_binding_message', undefined, '27');
export const InvalidClient = E('invalid_client', undefined, '28');
export const InvalidDpopProof = E('invalid_dpop_proof', undefined, '29');
export const InvalidRequestObject = E('invalid_request_object', undefined, '30');
export const InvalidRequestUri = E('invalid_request_uri', undefined, '31');
export const InvalidSoftwareStatement = E('invalid_software_statement', undefined, '32');
export const InvalidTarget = E('invalid_target', 'resource indicator is missing, or unknown', '33');
export const InvalidUserCode = E('invalid_user_code', undefined, '34');
export const LoginRequired = E('login_required', undefined, '35');
export const MissingUserCode = E('missing_user_code', undefined, '36');
export const RegistrationNotSupported = E('registration_not_supported', 'registration parameter provided but not supported', '37');
export const RequestNotSupported = E('request_not_supported', 'request parameter provided but not supported', '38');
export const RequestUriNotSupported = E('request_uri_not_supported', 'request_uri parameter provided but not supported', '39');
export const SlowDown = E('slow_down', 'you are polling too quickly and should back off at a reasonable rate', '40');
export const TemporarilyUnavailable = E('temporarily_unavailable', undefined, '41');
export const TransactionFailed = E('transaction_failed', undefined, '42');
export const UnapprovedSoftwareStatement = E('unapproved_software_statement', undefined, '43');
export const UnauthorizedClient = E('unauthorized_client', undefined, '44');
export const UnknownUserId = E('unknown_user_id', undefined, '45');
export const UnmetAuthenticationRequirements = E('unmet_authentication_requirements', undefined, '46');
export const UnsupportedGrantType = E('unsupported_grant_type', 'unsupported grant_type requested', '47');
export const UnsupportedResponseMode = E('unsupported_response_mode', 'unsupported response_mode requested', '48');
export const UnsupportedResponseType = E('unsupported_response_type', 'unsupported response_type requested', '49');
export const UseDpopNonce = E('use_dpop_nonce', undefined, '50');
