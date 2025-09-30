import {
  PERMISSIONS,
  ROLES,
  ROLE_PERMISSIONS,
  ROLE_NAMES,
  PERMISSION_UTILS,
  type TokenType,
} from '../constants/auth.constants';
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

/**
 * 권한 유틸리티 클래스
 * 비트마스크 기반 권한 관리를 위한 헬퍼 함수들
 */
export class PermissionUtils {
  /**
   * 사용자가 특정 권한을 가지고 있는지 확인
   * @param userPermissions 사용자의 권한 비트마스크
   * @param requiredPermission 확인할 권한
   * @returns 권한이 있는지 여부
   */
  static hasPermission(
    userPermissions: number,
    requiredPermission: number,
  ): boolean {
    return (userPermissions & requiredPermission) === requiredPermission;
  }

  /**
   * 사용자가 여러 권한 중 하나라도 가지고 있는지 확인
   * @param userPermissions 사용자의 권한 비트마스크
   * @param requiredPermissions 확인할 권한 배열
   * @returns 하나라도 권한이 있는지 여부
   */
  static hasAnyPermission(
    userPermissions: number,
    requiredPermissions: number[],
  ): boolean {
    return requiredPermissions.some((permission) =>
      this.hasPermission(userPermissions, permission),
    );
  }

  /**
   * 사용자가 모든 필요한 권한을 가지고 있는지 확인
   * @param userPermissions 사용자의 권한 비트마스크
   * @param requiredPermissions 확인할 권한 배열
   * @returns 모든 권한을 가지고 있는지 여부
   */
  static hasAllPermissions(
    userPermissions: number,
    requiredPermissions: number[],
  ): boolean {
    return requiredPermissions.every((permission) =>
      this.hasPermission(userPermissions, permission),
    );
  }

  /**
   * 권한 추가
   * @param currentPermissions 현재 권한
   * @param permissionsToAdd 추가할 권한들
   * @returns 새로운 권한 비트마스크
   */
  static addPermissions(
    currentPermissions: number,
    permissionsToAdd: number[],
  ): number {
    return permissionsToAdd.reduce(
      (acc, permission) => acc | permission,
      currentPermissions,
    );
  }

  /**
   * 권한 제거
   * @param currentPermissions 현재 권한
   * @param permissionsToRemove 제거할 권한들
   * @returns 새로운 권한 비트마스크
   */
  static removePermissions(
    currentPermissions: number,
    permissionsToRemove: number[],
  ): number {
    return permissionsToRemove.reduce(
      (acc, permission) => acc & ~permission,
      currentPermissions,
    );
  }

  /**
   * 권한 목록을 문자열로 변환
   * @param permissions 권한 비트마스크
   * @returns 권한 이름 배열
   */
  static getPermissionNames(permissions: number): string[] {
    const names: string[] = [];
    Object.entries(PERMISSIONS).forEach(([name, value]) => {
      if (this.hasPermission(permissions, value)) {
        names.push(name);
      }
    });
    return names;
  }

  /**
   * 역할 이름을 가져옴
   * @param permissions 권한 비트마스크
   * @returns 역할 이름 (가장 일치하는 것)
   */
  static getRoleName(permissions: number): string {
    // ADMIN 권한이 있는 경우 바로 시스템 관리자로 반환
    if (
      this.hasPermission(permissions, PERMISSION_UTILS.getAdminPermission())
    ) {
      return ROLE_NAMES[ROLES.ADMIN];
    }

    // 정확히 일치하는 역할 찾기 (ADMIN 제외)
    for (const [roleName, rolePermissions] of Object.entries(
      ROLE_PERMISSIONS,
    )) {
      if (
        roleName !== ROLES.ADMIN &&
        this.hasAllPermissions(permissions, [...rolePermissions])
      ) {
        return ROLE_NAMES[roleName as keyof typeof ROLE_NAMES];
      }
    }

    // 포함 관계로 가장 가까운 역할 찾기 (권한 레벨이 높은 순서로)
    const rolePriority = [
      ROLES.USER_MANAGER,
      ROLES.CLIENT_MANAGER,
      ROLES.TOKEN_MANAGER,
      ROLES.USER,
    ];
    for (const roleName of rolePriority) {
      const rolePermissions =
        ROLE_PERMISSIONS[roleName as keyof typeof ROLE_PERMISSIONS];
      if (this.hasAllPermissions(permissions, [...rolePermissions])) {
        return ROLE_NAMES[roleName as keyof typeof ROLE_NAMES];
      }
    }

    return '사용자 정의';
  }

  /**
   * 관리자 권한인지 확인 (ADMIN 권한의 비트를 가지고 있는지)
   * @param permissions 권한 비트마스크
   * @returns 관리자 권한 여부
   */
  static isAdmin(permissions: number): boolean {
    const adminPermission = PERMISSION_UTILS.getAdminPermission();
    return this.hasPermission(permissions, adminPermission);
  }

  /**
   * 기본 사용자 권한 생성
   * @returns 기본 권한 비트마스크
   */
  static getDefaultPermissions(): number {
    return ROLE_PERMISSIONS[ROLES.USER].reduce((acc, perm) => acc | perm, 0);
  }

  /**
   * 권한 비트마스크를 16진수 문자열로 변환
   * @param permissions 권한 비트마스크
   * @returns 16진수 문자열
   */
  static permissionsToHex(permissions: number): string {
    return '0x' + permissions.toString(16).toUpperCase();
  }

  /**
   * 16진수 문자열을 권한 비트마스크로 변환
   * @param hexString 16진수 문자열
   * @returns 권한 비트마스크
   */
  static hexToPermissions(hexString: string): number {
    return parseInt(hexString, 16);
  }
}
