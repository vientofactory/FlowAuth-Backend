import { HttpException, HttpStatus } from '@nestjs/common';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';

export interface OAuth2ErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

/**
 * RFC 6749 표준 OAuth2 에러 처리 클래스
 */
export class OAuth2Exception extends HttpException {
  constructor(
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
    statusCode: HttpStatus = HttpStatus.BAD_REQUEST,
  ) {
    const errorCode = OAUTH2_CONSTANTS.ERRORS[error];
    const errorDescription =
      description || OAUTH2_CONSTANTS.ERROR_DESCRIPTIONS[error];

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
 * OAuth2 Authorization 엔드포인트 관련 에러들
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
 * OAuth2 Token 엔드포인트 관련 에러들
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
 * OAuth2 리소스 접근 관련 에러들
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
 * OAuth2 에러 응답 헬퍼 함수들
 */
export class OAuth2ErrorHelper {
  /**
   * Authorization Code 관련 에러 생성
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
   * Token 엔드포인트 관련 에러 생성
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
   * 리소스 접근 관련 에러 생성
   */
  static invalidToken(description?: string): OAuth2ResourceException {
    return new OAuth2ResourceException('INVALID_TOKEN', description);
  }

  static insufficientScope(description?: string): OAuth2ResourceException {
    return new OAuth2ResourceException('INSUFFICIENT_SCOPE', description);
  }

  /**
   * 에러 응답을 리다이렉트 URL과 함께 생성
   */
  static createRedirectError(
    redirectUri: string,
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
  ): string {
    const params = new URLSearchParams({
      error: OAUTH2_CONSTANTS.ERRORS[error],
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
   * Fragment 방식으로 에러 응답 생성 (Implicit Grant용)
   */
  static createFragmentError(
    redirectUri: string,
    error: keyof typeof OAUTH2_CONSTANTS.ERRORS,
    description?: string,
    state?: string,
  ): string {
    const params = new URLSearchParams({
      error: OAUTH2_CONSTANTS.ERRORS[error],
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
