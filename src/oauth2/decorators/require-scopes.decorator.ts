import { SetMetadata } from '@nestjs/common';

export const SCOPES_KEY = 'oauth2_scopes';

/**
 * OAuth2 스코프 요구사항을 정의하는 데코레이터
 * @param scopes 필요한 스코프 목록
 */
export const RequireScopes = (...scopes: string[]) =>
  SetMetadata(SCOPES_KEY, scopes);

/**
 * 여러 스코프 중 하나만 있으면 되는 경우 사용하는 데코레이터
 * @param scopes 필요한 스코프 목록 중 하나
 */
export const RequireAnyScope = (...scopes: string[]) =>
  SetMetadata(SCOPES_KEY, { type: 'any', scopes });

/**
 * 모든 스코프가 필요한 경우 사용하는 데코레이터 (기본값)
 * @param scopes 필요한 모든 스코프 목록
 */
export const RequireAllScopes = (...scopes: string[]) =>
  SetMetadata(SCOPES_KEY, { type: 'all', scopes });
