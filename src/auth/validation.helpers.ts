import { BadRequestException } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import type { AuthenticatedRequest } from '../types/auth.types';
import { VALIDATION_CONSTANTS } from '../constants/validation.constants';

/**
 * 검증 및 타입 가드 헬퍼 클래스
 * @deprecated ValidationService 사용을 권장합니다
 */
export class ValidationHelpers {
  /**
   * 이메일 형식 검증 헬퍼 메소드
   * @deprecated ValidationService.validateEmail 사용을 권장합니다
   */
  static validateEmail(email: string): void {
    if (!VALIDATION_CONSTANTS.EMAIL.REGEX.test(email)) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.EMAIL.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }
  }

  /**
   * 2FA 토큰 형식 검증 헬퍼 메소드 (6자리 숫자)
   * @deprecated ValidationService.validateTwoFactorToken 사용을 권장합니다
   */
  static validateTwoFactorToken(token: string): void {
    if (!VALIDATION_CONSTANTS.TWO_FACTOR_TOKEN.REGEX.test(token)) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.TWO_FACTOR_TOKEN.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }
  }

  /**
   * 백업 코드 형식 검증 헬퍼 메소드 (XXXX-XXXX 형식)
   * @deprecated ValidationService.validateBackupCode 사용을 권장합니다
   */
  static validateBackupCode(code: string): void {
    if (!VALIDATION_CONSTANTS.BACKUP_CODE.REGEX.test(code.toUpperCase())) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.BACKUP_CODE.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }
  }

  /**
   * Authorization 헤더 검증 및 토큰 추출 헬퍼 메소드
   */
  static extractBearerToken(req: ExpressRequest): string {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.AUTHORIZATION.ERROR_MESSAGES.HEADER_REQUIRED,
      );
    }

    if (typeof authHeader !== 'string') {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.AUTHORIZATION.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }

    if (
      !authHeader.startsWith(VALIDATION_CONSTANTS.AUTHORIZATION.BEARER_PREFIX)
    ) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.AUTHORIZATION.ERROR_MESSAGES.BEARER_REQUIRED,
      );
    }

    const token = authHeader.substring(
      VALIDATION_CONSTANTS.AUTHORIZATION.BEARER_PREFIX.length,
    );
    if (token?.trim().length === 0) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.AUTHORIZATION.ERROR_MESSAGES.TOKEN_EMPTY,
      );
    }

    return token;
  }

  /**
   * AuthenticatedRequest 타입 가드
   */
  static isAuthenticatedRequest(req: any): req is AuthenticatedRequest {
    return (
      req &&
      typeof req === 'object' &&
      req.user &&
      typeof req.user === 'object' &&
      typeof req.user.id === 'number' &&
      req.user.id > 0
    );
  }

  /**
   * 요청이 인증되었는지 검증하는 헬퍼 메소드
   */
  static validateAuthenticatedRequest(
    req: any,
  ): asserts req is AuthenticatedRequest {
    if (!ValidationHelpers.isAuthenticatedRequest(req)) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.GENERAL.ERROR_MESSAGES.UNAUTHENTICATED,
      );
    }
  }

  /**
   * ID 파라미터를 안전하게 파싱하는 헬퍼 메소드
   * @deprecated ValidationService.validateIdParam 사용을 권장합니다
   */
  static parseIdParam(idParam: string): number {
    const id = parseInt(idParam, 10);
    if (isNaN(id) || id <= 0) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.GENERAL.ERROR_MESSAGES.INVALID_ID,
      );
    }
    return id;
  }
}
