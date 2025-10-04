import type { User } from '../../auth/user.entity';
import { PermissionUtils } from '../../utils/permission.util';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * OAuth2 UserInfo 응답 타입 (OIDC 호환)
 */
export interface OAuth2UserInfoResponse {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  updated_at?: number;
  roles?: string[];
}

/**
 * 스코프별 필드 매핑 정의
 */
export interface ScopeFieldMapping {
  scope: string;
  fields: (keyof Omit<OAuth2UserInfoResponse, 'sub'>)[];
  fieldMapper?: (user: User) => Partial<OAuth2UserInfoResponse>;
}

/**
 * OAuth2 스코프 기반 UserInfo 필드 매핑 설정 (OIDC 호환)
 */
const SCOPE_FIELD_MAPPINGS: ScopeFieldMapping[] = [
  {
    scope: 'profile',
    fields: [
      'name',
      'given_name',
      'family_name',
      'preferred_username',
      'profile',
      'picture',
      'updated_at',
      'roles',
    ],
  },
  {
    scope: 'email',
    fields: ['email', 'email_verified'],
  },
  // 기존 호환성을 위한 스코프
  {
    scope: 'identify',
    fields: ['preferred_username', 'roles'],
  },
];

/**
 * OAuth2 UserInfo 응답 생성 유틸리티 클래스
 */
@Injectable()
export class OAuth2UserInfoBuilder {
  constructor(private readonly configService: ConfigService) {}
  /**
   * 주어진 스코프 목록에 따라 UserInfo 응답을 생성합니다.
   *
   * @param user 사용자 엔티티
   * @param scopes OAuth2 스코프 배열
   * @returns UserInfo 응답 객체
   */
  buildUserInfo(user: User, scopes: string[]): OAuth2UserInfoResponse {
    return OAuth2UserInfoBuilder.buildUserInfoWithConfig(
      user,
      scopes,
      this.configService,
    );
  }

  /**
   * 주어진 스코프 목록에 따라 UserInfo 응답을 생성합니다. (ConfigService 사용)
   *
   * @param user 사용자 엔티티
   * @param scopes OAuth2 스코프 배열
   * @param configService ConfigService 인스턴스
   * @returns UserInfo 응답 객체
   */
  static buildUserInfoWithConfig(
    user: User,
    scopes: string[],
    configService: ConfigService,
  ): OAuth2UserInfoResponse {
    // 기본 응답 (항상 포함되는 필드)
    const response: OAuth2UserInfoResponse = {
      sub: user.id.toString(), // OpenID Connect 표준에 따라 항상 포함
    };

    // 각 스코프에 따라 필드 추가
    for (const scope of scopes) {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope(scope);
      if (fields.length > 0) {
        const fieldData = OAuth2UserInfoBuilder.getFieldDataForScopeWithConfig(
          user,
          scope,
          configService,
        );
        Object.assign(response, fieldData);
      }
    }

    return response;
  }

  /**
   * 주어진 스코프 목록에 따라 UserInfo 응답을 생성합니다. (하위 호환성용)
   *
   * @param user 사용자 엔티티
   * @param scopes OAuth2 스코프 배열
   * @returns UserInfo 응답 객체
   * @deprecated Use buildUserInfoWithConfig instead
   */
  static buildUserInfo(user: User, scopes: string[]): OAuth2UserInfoResponse {
    // 기본 응답 (항상 포함되는 필드)
    const response: OAuth2UserInfoResponse = {
      sub: user.id.toString(), // OpenID Connect 표준에 따라 항상 포함
    };

    // 각 스코프에 따라 필드 추가
    for (const scope of scopes) {
      const mapping = SCOPE_FIELD_MAPPINGS.find((m) => m.scope === scope);
      if (mapping) {
        // 하위 호환성을 위해 process.env 사용 (권장하지 않음)
        const fieldData = OAuth2UserInfoBuilder.getFieldDataForScopeLegacy(
          user,
          scope,
        );
        Object.assign(response, fieldData);
      }
    }

    return response;
  }

  /**
   * 특정 스코프에 대한 필드 데이터를 생성합니다. (ConfigService 사용)
   *
   * @param user 사용자 엔티티
   * @param scope 스코프 이름
   * @param configService ConfigService 인스턴스
   * @returns 필드 데이터 객체
   */
  private static getFieldDataForScopeWithConfig(
    user: User,
    scope: string,
    configService: ConfigService,
  ): Partial<OAuth2UserInfoResponse> {
    switch (scope) {
      case 'profile':
        return {
          name: user.username, // 전체 이름으로 사용자명 사용
          given_name:
            user.firstName || user.username.split('_')[0] || user.username,
          family_name: user.lastName || '',
          preferred_username: user.username,
          profile: `${configService.get<string>('BACKEND_URL', 'http://localhost:3000')}/users/${user.id}`,
          picture: user.avatar || undefined,
          updated_at: Math.floor(
            (user.updatedAt?.getTime() || Date.now()) / 1000,
          ),
          roles: [PermissionUtils.getRoleName(user.permissions)],
        };
      case 'email':
        return {
          email: user.email,
          email_verified: !!user.isEmailVerified,
        };
      case 'identify':
        return {
          preferred_username: user.username,
          roles: [PermissionUtils.getRoleName(user.permissions)],
        };
      default:
        return {};
    }
  }

  /**
   * 특정 스코프에 대한 필드 데이터를 생성합니다. (하위 호환성용)
   *
   * @param user 사용자 엔티티
   * @param scope 스코프 이름
   * @returns 필드 데이터 객체
   * @deprecated Use getFieldDataForScopeWithConfig instead
   */
  private static getFieldDataForScopeLegacy(
    user: User,
    scope: string,
  ): Partial<OAuth2UserInfoResponse> {
    switch (scope) {
      case 'profile':
        return {
          name: user.username, // 전체 이름으로 사용자명 사용
          given_name:
            user.firstName || user.username.split('_')[0] || user.username,
          family_name: user.lastName || '',
          preferred_username: user.username,
          profile: `${process.env.BACKEND_URL || 'http://localhost:3000'}/users/${user.id}`,
          picture: user.avatar || undefined,
          updated_at: Math.floor(
            (user.updatedAt?.getTime() || Date.now()) / 1000,
          ),
          roles: [PermissionUtils.getRoleName(user.permissions)],
        };
      case 'email':
        return {
          email: user.email,
          email_verified: !!user.isEmailVerified,
        };
      case 'identify':
        return {
          preferred_username: user.username,
          roles: [PermissionUtils.getRoleName(user.permissions)],
        };
      default:
        return {};
    }
  }

  /**
   * 특정 스코프가 지원되는지 확인합니다.
   *
   * @param scope 확인할 스코프
   * @returns 지원 여부
   */
  static isScopeSupported(scope: string): boolean {
    return SCOPE_FIELD_MAPPINGS.some((mapping) => mapping.scope === scope);
  }

  /**
   * 지원되는 모든 스코프 목록을 반환합니다.
   *
   * @returns 스코프 배열
   */
  static getSupportedScopes(): string[] {
    return SCOPE_FIELD_MAPPINGS.map((mapping) => mapping.scope);
  }

  /**
   * 특정 스코프가 노출하는 필드 목록을 반환합니다.
   *
   * @param scope 스코프 이름
   * @returns 필드 이름 배열
   */
  static getFieldsForScope(
    scope: string,
  ): (keyof Omit<OAuth2UserInfoResponse, 'sub'>)[] {
    const mapping = SCOPE_FIELD_MAPPINGS.find((m) => m.scope === scope);
    return mapping?.fields || [];
  }

  /**
   * 새로운 스코프 매핑을 등록합니다.
   * 확장성을 위해 제공되는 메서드입니다.
   *
   * @param mapping 스코프 필드 매핑
   */
  static registerScopeMapping(mapping: ScopeFieldMapping): void {
    // 중복 등록 방지
    if (SCOPE_FIELD_MAPPINGS.some((m) => m.scope === mapping.scope)) {
      throw new Error(`Scope '${mapping.scope}' is already registered`);
    }
    SCOPE_FIELD_MAPPINGS.push(mapping);
  }
}

/**
 * 범용 OAuth2 UserInfo 생성 함수
 * 클래스를 사용하지 않고 함수 형태로도 제공
 *
 * @param user 사용자 엔티티
 * @param scopes OAuth2 스코프 배열
 * @returns UserInfo 응답 객체
 * @deprecated Use OAuth2UserInfoBuilder service instead
 */
export function buildOAuth2UserInfo(
  user: User,
  scopes: string[],
): OAuth2UserInfoResponse {
  return OAuth2UserInfoBuilder.buildUserInfo(user, scopes);
}
