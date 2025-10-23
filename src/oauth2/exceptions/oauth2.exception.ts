import { HttpException, HttpStatus } from '@nestjs/common';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';

export interface OAuth2ErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

/**
 * Helper class for type-safe OAuth2 constants access
 */
class OAuth2ConstantsHelper {
  private static readonly ERROR_MAP = new Map(
    Object.entries(OAUTH2_CONSTANTS.ERRORS),
  );

  private static readonly ERROR_DESCRIPTION_MAP = new Map(
    Object.entries(OAUTH2_CONSTANTS.ERROR_DESCRIPTIONS),
  );

  static getErrorCode(error: keyof typeof OAUTH2_CONSTANTS.ERRORS): string {
    return this.ERROR_MAP.get(error) ?? 'invalid_request';
  }

  static getErrorDescription(
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
  ): string {
    return this.ERROR_DESCRIPTION_MAP.get(error) ?? 'An error occurred';
  }
}

/**
 * RFC 6749 standard OAuth2 error handling class
 */
export class OAuth2Exception extends HttpException {
  constructor(
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
    statusCode: HttpStatus = HttpStatus.BAD_REQUEST,
  ) {
    // Type-safe constants access
    const errorCode = OAuth2ConstantsHelper.getErrorCode(error);
    const errorDescription =
      description ?? OAuth2ConstantsHelper.getErrorDescription(error);

    const response: OAuth2ErrorResponse = {
      error: errorCode,
      error_description: errorDescription,
    };

    if (state) {
      response.state = state;
    }

    super(response, statusCode);
  }
}

/**
 * OAuth2 Authorization endpoint related errors
 */
export class OAuth2AuthorizationException extends OAuth2Exception {
  constructor(
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
  ) {
    super(error, description, state, HttpStatus.BAD_REQUEST);
  }
}

/**
 * OAuth2 Token endpoint related errors
 */
export class OAuth2TokenException extends OAuth2Exception {
  constructor(
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
  ) {
    const statusCode =
      error === 'INVALID_CLIENT'
        ? HttpStatus.UNAUTHORIZED
        : HttpStatus.BAD_REQUEST;

    super(error, description, undefined, statusCode);
  }
}

/**
 * OAuth2 resource access related errors
 */
export class OAuth2ResourceException extends OAuth2Exception {
  constructor(
    error: 'INVALID_TOKEN' | 'INSUFFICIENT_SCOPE',
    description?: string,
  ) {
    super(error, description, undefined, HttpStatus.UNAUTHORIZED);
  }
}

/**
 * OAuth2 error response helper functions
 */
export class OAuth2ErrorHelper {
  /**
   * Authorization Code related error generation
   */
  static invalidRequest(
    description?: string,
    state?: string,
  ): OAuth2AuthorizationException {
    return new OAuth2AuthorizationException(
      'INVALID_REQUEST',
      description,
      state,
    );
  }

  static unauthorizedClient(
    description?: string,
    state?: string,
  ): OAuth2AuthorizationException {
    return new OAuth2AuthorizationException(
      'UNAUTHORIZED_CLIENT',
      description,
      state,
    );
  }

  static accessDenied(
    description?: string,
    state?: string,
  ): OAuth2AuthorizationException {
    return new OAuth2AuthorizationException(
      'ACCESS_DENIED',
      description,
      state,
    );
  }

  static unsupportedResponseType(
    description?: string,
    state?: string,
  ): OAuth2AuthorizationException {
    return new OAuth2AuthorizationException(
      'UNSUPPORTED_RESPONSE_TYPE',
      description,
      state,
    );
  }

  static invalidScope(
    description?: string,
    state?: string,
  ): OAuth2AuthorizationException {
    return new OAuth2AuthorizationException(
      'INVALID_SCOPE',
      description,
      state,
    );
  }

  static serverError(
    description?: string,
    state?: string,
  ): OAuth2AuthorizationException {
    return new OAuth2AuthorizationException('SERVER_ERROR', description, state);
  }

  /**
   * Token endpoint related error generation
   */
  static invalidClient(description?: string): OAuth2TokenException {
    return new OAuth2TokenException('INVALID_CLIENT', description);
  }

  static invalidGrant(description?: string): OAuth2TokenException {
    return new OAuth2TokenException('INVALID_GRANT', description);
  }

  static unsupportedGrantType(description?: string): OAuth2TokenException {
    return new OAuth2TokenException('UNSUPPORTED_GRANT_TYPE', description);
  }

  /**
   * Resource access related error generation
   */
  static invalidToken(description?: string): OAuth2ResourceException {
    return new OAuth2ResourceException('INVALID_TOKEN', description);
  }

  static insufficientScope(description?: string): OAuth2ResourceException {
    return new OAuth2ResourceException('INSUFFICIENT_SCOPE', description);
  }

  /**
   * Generate error response with redirect URL
   */
  static createRedirectError(
    redirectUri: string,
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
  ): string {
    const params = new URLSearchParams({
      error: OAuth2ConstantsHelper.getErrorCode(error),
    });

    if (description) {
      params.append('error_description', description);
    }

    if (state) {
      params.append('state', state);
    }

    const separator = redirectUri.includes('?') ? '&' : '?';
    return `${redirectUri}${separator}${params.toString()}`;
  }

  /**
   * Generate error response in fragment format (for Implicit Grant)
   */
  static createFragmentError(
    redirectUri: string,
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
  ): string {
    const params = new URLSearchParams({
      error: OAuth2ConstantsHelper.getErrorCode(error),
    });

    if (description) {
      params.append('error_description', description);
    }

    if (state) {
      params.append('state', state);
    }

    return `${redirectUri}#${params.toString()}`;
  }
}
