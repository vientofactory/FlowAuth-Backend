import { HttpException } from '@nestjs/common';
import { ProblemDetailsDto } from '../dto/response.dto';

/**
 * RFC 7807 Problem Details 유틸리티
 */
export class ProblemDetailsUtil {
  private static readonly RFC7807_BASE_URI =
    'https://tools.ietf.org/html/rfc7807';

  /**
   * HTTP 예외를 RFC 7807 Problem Details로 변환
   */
  static fromHttpException(
    exception: HttpException,
    instance?: string,
  ): ProblemDetailsDto {
    const status = exception.getStatus();
    const response = exception.getResponse();

    let title: string;
    let detail: string;
    let type: string;
    const extensions: Record<string, unknown> = {};

    // 응답이 객체인 경우
    if (typeof response === 'object' && response !== null) {
      const errorResponse = response as Record<string, unknown>;
      detail =
        (errorResponse.message as string) ??
        (errorResponse.error_description as string) ??
        'An error occurred';
      if (errorResponse.error) {
        extensions.error = errorResponse.error;
      }
      if (errorResponse.error_description) {
        extensions.error_description = errorResponse.error_description;
      }
      if (errorResponse.state) {
        extensions.state = errorResponse.state;
      }
    } else if (typeof response === 'string') {
      detail = response;
    } else {
      detail = 'An error occurred';
    }

    // 상태 코드에 따른 기본 설정
    switch (status) {
      case 400:
        type = `${this.RFC7807_BASE_URI}#section-6.5.1`;
        title = 'Bad Request';
        break;
      case 401:
        type = `${this.RFC7807_BASE_URI}#section-3.1`;
        title = 'Unauthorized';
        break;
      case 403:
        type = `${this.RFC7807_BASE_URI}#section-6.5.3`;
        title = 'Forbidden';
        break;
      case 404:
        type = `${this.RFC7807_BASE_URI}#section-6.5.4`;
        title = 'Not Found';
        break;
      case 409:
        type = `${this.RFC7807_BASE_URI}#section-6.5.8`;
        title = 'Conflict';
        break;
      case 422:
        type = `${this.RFC7807_BASE_URI}#section-6.5.1`;
        title = 'Unprocessable Entity';
        break;
      case 500:
        type = `${this.RFC7807_BASE_URI}#section-6.6.1`;
        title = 'Internal Server Error';
        break;
      default:
        type = `${this.RFC7807_BASE_URI}#section-6.6.1`;
        title = 'Internal Server Error';
    }

    return {
      type,
      title,
      detail,
      status,
      instance,
      ...(Object.keys(extensions).length > 0 ? { extensions } : {}),
    };
  }

  /**
   * OAuth2 에러를 RFC 7807 Problem Details로 변환
   */
  static fromOAuth2Error(
    error: string,
    errorDescription: string,
    status: number = 400,
    instance?: string,
    state?: string,
  ): ProblemDetailsDto {
    const extensions: Record<string, unknown> = {
      error,
      error_description: errorDescription,
    };

    if (state) {
      extensions.state = state;
    }

    let title: string;
    let type: string;

    // OAuth2 에러 코드에 따른 설정
    switch (error) {
      case 'invalid_request':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Invalid Request';
        break;
      case 'invalid_client':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Invalid Client';
        break;
      case 'invalid_grant':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Invalid Grant';
        break;
      case 'unauthorized_client':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Unauthorized Client';
        break;
      case 'unsupported_grant_type':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Unsupported Grant Type';
        break;
      case 'invalid_scope':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Invalid Scope';
        break;
      case 'access_denied':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Access Denied';
        break;
      case 'unsupported_response_type':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Unsupported Response Type';
        break;
      case 'server_error':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Server Error';
        break;
      case 'temporarily_unavailable':
        type = 'https://tools.ietf.org/html/rfc6749#section-5.2';
        title = 'Temporarily Unavailable';
        break;
      default:
        type = `${this.RFC7807_BASE_URI}#section-6.6.1`;
        title = 'Error';
    }

    return {
      type,
      title,
      detail: errorDescription,
      status,
      instance,
      extensions,
    };
  }

  /**
   * 일반 에러를 RFC 7807 Problem Details로 변환
   */
  static fromError(
    error: Error,
    status: number = 500,
    instance?: string,
    extensions?: Record<string, unknown>,
  ): ProblemDetailsDto {
    let title: string;
    let type: string;

    switch (status) {
      case 400:
        type = `${this.RFC7807_BASE_URI}#section-6.5.1`;
        title = 'Bad Request';
        break;
      case 401:
        type = `${this.RFC7807_BASE_URI}#section-3.1`;
        title = 'Unauthorized';
        break;
      case 403:
        type = `${this.RFC7807_BASE_URI}#section-6.5.3`;
        title = 'Forbidden';
        break;
      case 404:
        type = `${this.RFC7807_BASE_URI}#section-6.5.4`;
        title = 'Not Found';
        break;
      case 409:
        type = `${this.RFC7807_BASE_URI}#section-6.5.8`;
        title = 'Conflict';
        break;
      case 422:
        type = `${this.RFC7807_BASE_URI}#section-6.5.1`;
        title = 'Unprocessable Entity';
        break;
      case 500:
        type = `${this.RFC7807_BASE_URI}#section-6.6.1`;
        title = 'Internal Server Error';
        break;
      default:
        type = `${this.RFC7807_BASE_URI}#section-6.6.1`;
        title = 'Internal Server Error';
    }

    return {
      type,
      title,
      detail: error.message,
      status,
      instance,
      extensions,
    };
  }

  /**
   * 표준 성공 응답 생성
   */
  static createSuccessResponse<T>(
    data: T,
    message: string = 'Request completed successfully',
  ): { success: boolean; message: string; data: T; timestamp: string } {
    return {
      success: true,
      message,
      data,
      timestamp: new Date().toISOString(),
    };
  }
}
