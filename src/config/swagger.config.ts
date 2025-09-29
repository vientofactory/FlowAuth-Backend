import { DocumentBuilder } from '@nestjs/swagger';

/**
 * Swagger API Documentation Configuration
 * FlowAuth OAuth2 시스템의 API 문서화 설정
 */

/**
 * OAuth2 스코프 정의
 */
export const OAUTH2_SCOPES = {
  identify: '계정의 기본 정보 읽기 (사용자 ID, 이름 등)',
  email: '사용자 이메일 주소 읽기',
  basic: '기본 접근 권한',
};
export const API_TAGS = {
  SYSTEM: 'System',
  AUTHENTICATION: 'Authentication',
  OAUTH2_FLOW: 'OAuth2 Flow',
  CLIENT_MANAGEMENT: 'Client Management',
  USER_MANAGEMENT: 'User Management',
  FILE_UPLOAD: 'File Upload',
  DASHBOARD: 'Dashboard',
} as const;

/**
 * API 태그 설명
 */
export const API_TAG_DESCRIPTIONS = {
  [API_TAGS.SYSTEM]: '시스템 상태 및 기본 정보',
  [API_TAGS.AUTHENTICATION]: '사용자 인증 및 계정 관리',
  [API_TAGS.OAUTH2_FLOW]: 'OAuth2 인증 플로우 및 토큰 관리',
  [API_TAGS.CLIENT_MANAGEMENT]: 'OAuth2 클라이언트 애플리케이션 관리',
  [API_TAGS.USER_MANAGEMENT]: '사용자 관리 (관리자 전용)',
  [API_TAGS.FILE_UPLOAD]: '파일 업로드 및 관리',
  [API_TAGS.DASHBOARD]: '대시보드 및 통계 정보',
} as const;

/**
 * API 문서 설명
 */
export const API_DESCRIPTION = `
# FlowAuth OAuth2 Authentication System

FlowAuth는 오픈소스 OAuth2 인증 서버로, 안전하고 확장 가능한 인증 및 권한 부여 솔루션을 제공합니다. 이 문서는 FlowAuth의 API 엔드포인트와 사용법을 설명합니다.

## 주요 기능
- OAuth2 Authorization Code Flow 지원
- PKCE (Proof Key for Code Exchange) 보안 확장
- 세밀한 스코프 기반 접근 제어
- 클라이언트 애플리케이션 관리
- 파일 업로드 및 관리

## 인증 방식
- **Bearer Token**: 대부분의 API 엔드포인트에서 사용
- **OAuth2**: OAuth2 플로우를 통한 third-party 애플리케이션 인증
`;

/**
 * Swagger DocumentBuilder 설정을 생성합니다.
 */
export function createSwaggerConfig() {
  return (
    new DocumentBuilder()
      .setTitle('FlowAuth API')
      .setDescription(API_DESCRIPTION)
      .setVersion('1.0.0')
      .setContact(
        'FlowAuth Project',
        'https://github.com/vientofactory/FlowAuth',
        'op@viento.me',
      )
      .setLicense('MIT', 'https://opensource.org/licenses/MIT')

      // Security schemes
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          name: 'JWT',
          description: 'FlowAuth JWT 토큰을 입력하세요',
          in: 'header',
        },
        'JWT-auth',
      )
      .addOAuth2(
        {
          type: 'oauth2',
          flows: {
            authorizationCode: {
              authorizationUrl: '/oauth2/authorize',
              tokenUrl: '/oauth2/token',
              scopes: OAUTH2_SCOPES,
            },
          },
        },
        'OAuth2',
      )

      // API Tags for categorization
      .addTag(API_TAGS.SYSTEM, API_TAG_DESCRIPTIONS[API_TAGS.SYSTEM])
      .addTag(
        API_TAGS.AUTHENTICATION,
        API_TAG_DESCRIPTIONS[API_TAGS.AUTHENTICATION],
      )
      .addTag(API_TAGS.OAUTH2_FLOW, API_TAG_DESCRIPTIONS[API_TAGS.OAUTH2_FLOW])
      .addTag(
        API_TAGS.CLIENT_MANAGEMENT,
        API_TAG_DESCRIPTIONS[API_TAGS.CLIENT_MANAGEMENT],
      )
      .addTag(
        API_TAGS.USER_MANAGEMENT,
        API_TAG_DESCRIPTIONS[API_TAGS.USER_MANAGEMENT],
      )
      .addTag(API_TAGS.FILE_UPLOAD, API_TAG_DESCRIPTIONS[API_TAGS.FILE_UPLOAD])
      .addTag(API_TAGS.DASHBOARD, API_TAG_DESCRIPTIONS[API_TAGS.DASHBOARD])
      .build()
  );
}

/**
 * Swagger UI 설정 옵션
 */
export const SWAGGER_SETUP_OPTIONS = {
  customSiteTitle: 'FlowAuth API Documentation',
  customfavIcon: '/favicon.ico',
  customJs: [
    'https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js',
    'https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js',
  ],
  customCssUrl: ['https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css'],
  jsonDocumentUrl: 'swagger/json',
};

/**
 * Swagger 문서 생성 옵션
 */
export const SWAGGER_DOCUMENT_OPTIONS = {
  operationIdFactory: (controllerKey: string, methodKey: string) => methodKey,
};
