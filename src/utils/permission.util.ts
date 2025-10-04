import { TokenType } from '@flowauth/shared';
import { JwtService } from '@nestjs/jwt';
import type { JwtPayload } from '../types/auth.types';

/**
 * 토큰 유틸리티 클래스
 * JWT 토큰 타입 검증을 위한 헬퍼 함수들
 */
export class TokenUtils {
  /**
   * 토큰 타입 검증
   * @param token JWT 토큰 문자열
   * @param expectedType 예상되는 토큰 타입
   * @param jwtService JWT 서비스 인스턴스
   * @returns 토큰 타입이 일치하는지 여부
   */
  static async validateTokenType(
    token: string,
    expectedType: TokenType,
    jwtService: JwtService,
  ): Promise<boolean> {
    try {
      const payload = await jwtService.verifyAsync<JwtPayload>(token);
      return payload.type === expectedType;
    } catch {
      return false;
    }
  }

  /**
   * 토큰에서 페이로드 추출 및 타입 검증
   * @param token JWT 토큰 문자열
   * @param expectedType 예상되는 토큰 타입
   * @param jwtService JWT 서비스 인스턴스
   * @returns 검증된 페이로드 또는 null
   */
  static async extractAndValidatePayload(
    token: string,
    expectedType: TokenType,
    jwtService: JwtService,
  ): Promise<JwtPayload | null> {
    try {
      const payload = await jwtService.verifyAsync<JwtPayload>(token);
      if (payload.type === expectedType) {
        return payload;
      }
      return null;
    } catch {
      return null;
    }
  }
}

// Re-export PermissionUtils from shared
export { PermissionUtils } from '@flowauth/shared';
