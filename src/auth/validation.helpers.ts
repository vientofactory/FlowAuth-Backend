import { BadRequestException } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import type { AuthenticatedRequest } from '../types/auth.types';

/**
 * 검증 및 타입 가드 헬퍼 클래스
 */
export class ValidationHelpers {
  /**
   * 이메일 형식 검증 헬퍼 메소드
   */
  static validateEmail(email: string): void {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('올바른 이메일 형식이 아닙니다.');
    }
  }

  /**
   * 2FA 토큰 형식 검증 헬퍼 메소드 (6자리 숫자)
   */
  static validateTwoFactorToken(token: string): void {
    const tokenRegex = /^\d{6}$/;
    if (!tokenRegex.test(token)) {
      throw new BadRequestException('2FA 토큰은 6자리 숫자여야 합니다.');
    }
  }

  /**
   * 백업 코드 형식 검증 헬퍼 메소드 (XXXX-XXXX 형식)
   */
  static validateBackupCode(code: string): void {
    const codeRegex = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;
    if (!codeRegex.test(code.toUpperCase())) {
      throw new BadRequestException('백업 코드는 XXXX-XXXX 형식이어야 합니다.');
    }
  }

  /**
   * Authorization 헤더 검증 및 토큰 추출 헬퍼 메소드
   */
  static extractBearerToken(req: ExpressRequest): string {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new BadRequestException('Authorization 헤더가 필요합니다.');
    }

    if (typeof authHeader !== 'string') {
      throw new BadRequestException('잘못된 Authorization 헤더 형식입니다.');
    }

    if (!authHeader.startsWith('Bearer ')) {
      throw new BadRequestException('Bearer 토큰 형식이 필요합니다.');
    }

    const token = authHeader.substring(7);
    if (!token || token.trim().length === 0) {
      throw new BadRequestException('토큰 값이 비어있습니다.');
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
      throw new BadRequestException('인증되지 않은 요청입니다.');
    }
  }

  /**
   * ID 파라미터를 안전하게 파싱하는 헬퍼 메소드
   */
  static parseIdParam(idParam: string): number {
    const id = parseInt(idParam, 10);
    if (isNaN(id) || id <= 0) {
      throw new BadRequestException('Invalid ID parameter');
    }
    return id;
  }
}
