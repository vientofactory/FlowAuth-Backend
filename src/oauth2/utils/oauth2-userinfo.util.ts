import type { User } from '../../user/user.entity';
import { PermissionUtils } from '../../utils/permission.util';

/**
 * OAuth2 UserInfo 응답 타입
 */
export interface OAuth2UserInfoResponse {
  sub: string;
  email?: string;
  username?: string;
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
 * OAuth2 스코프 기반 UserInfo 필드 매핑 설정
 */
const SCOPE_FIELD_MAPPINGS: ScopeFieldMapping[] = [
  {
    scope: 'email',
    fields: ['email'],
    fieldMapper: (user: User) => ({
      email: user.email,
    }),
  },
  {
    scope: 'identify',
    fields: ['username', 'roles'],
    fieldMapper: (user: User) => ({
      username: user.username,
      roles: [PermissionUtils.getRoleName(user.permissions)],
    }),
  },
  // 추가 스코프 매핑은 여기에 정의
];

/**
 * OAuth2 UserInfo 응답 생성 유틸리티 클래스
 */
export class OAuth2UserInfoBuilder {
  /**
   * 주어진 스코프 목록에 따라 UserInfo 응답을 생성합니다.
   *
   * @param user 사용자 엔티티
   * @param scopes OAuth2 스코프 배열
   * @returns UserInfo 응답 객체
   */
  static buildUserInfo(user: User, scopes: string[]): OAuth2UserInfoResponse {
    // 기본 응답 (항상 포함되는 필드)
    const response: OAuth2UserInfoResponse = {
      sub: user.id.toString(), // OpenID Connect 표준에 따라 항상 포함
    };

    // 각 스코프에 따라 필드 추가
    for (const scope of scopes) {
      const mapping = SCOPE_FIELD_MAPPINGS.find((m) => m.scope === scope);
      if (mapping && mapping.fieldMapper) {
        const fields = mapping.fieldMapper(user);
        Object.assign(response, fields);
      }
    }

    return response;
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
 */
export function buildOAuth2UserInfo(
  user: User,
  scopes: string[],
): OAuth2UserInfoResponse {
  return OAuth2UserInfoBuilder.buildUserInfo(user, scopes);
}
