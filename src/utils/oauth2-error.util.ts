import { BadRequestException } from '@nestjs/common';

/**
 * OAuth2 표준 에러 코드 타입
 */
export type OAuth2ErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'unauthorized_client'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'invalid_grant'
  | 'unsupported_grant_type'
  | 'server_error'
  | 'temporarily_unavailable';

/**
 * OAuth2 에러 응답 인터페이스
 */
export interface OAuth2ErrorResponse {
  error: OAuth2ErrorCode;
  error_description: string;
}

/**
 * BadRequestException을 OAuth2 표준 에러로 변환하는 유틸리티 함수
 *
 * @param error - 변환할 BadRequestException
 * @returns OAuth2 표준 에러 응답
 */
export function mapExceptionToOAuth2Error(
  error: BadRequestException,
): OAuth2ErrorResponse {
  const message = error.message;
  let errorCode: OAuth2ErrorCode = 'invalid_request';
  const errorDescription = message;

  // 메시지 내용에 따라 적절한 OAuth2 에러 코드로 매핑
  if (message.includes('client_id') || message.includes('client_secret')) {
    errorCode = 'invalid_client';
  } else if (message.includes('code') || message.includes('authorization')) {
    errorCode = 'invalid_grant';
  } else if (message.includes('scope')) {
    errorCode = 'invalid_scope';
  } else if (message.includes('rate limit')) {
    errorCode = 'temporarily_unavailable';
  }

  return {
    error: errorCode,
    error_description: errorDescription,
  };
}

/**
 * OAuth2 표준 에러 응답을 생성하는 헬퍼 함수
 *
 * @param errorCode - OAuth2 에러 코드
 * @param errorDescription - 에러 설명
 * @returns OAuth2 에러 응답 객체
 */
export function createOAuth2Error(
  errorCode: OAuth2ErrorCode,
  errorDescription: string,
): OAuth2ErrorResponse {
  return {
    error: errorCode,
    error_description: errorDescription,
  };
}
