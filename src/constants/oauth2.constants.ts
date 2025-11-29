// OAuth 관련 타입 정의
export type OAuth2GrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials';
export type OAuth2ResponseType =
  // Authorization Code Grant
  | 'code'
  // ID Token (OpenID Connect)
  | 'id_token'
  // Hybrid Flow(Authorization Code + ID Token)
  | 'code id_token';
export type OAuth2TokenType = 'Bearer';

// OAuth2 관련 상수들
export const OAUTH2_CONSTANTS = {
  SUPPORTED_RESPONSE_TYPES: ['code', 'id_token', 'code id_token'] as const,
  SUPPORTED_GRANT_TYPES: [
    'authorization_code',
    'refresh_token',
    'client_credentials',
  ] as const,
  // Response Type 상수들
  RESPONSE_TYPES: {
    CODE: 'code',
    ID_TOKEN: 'id_token',
    CODE_ID_TOKEN: 'code id_token',
  } as const,
  // Token Type 상수들
  TOKEN_TYPES: {
    BEARER: 'Bearer',
  } as const,
  // OAuth2 Error 상수들 (RFC 6749 표준)
  ERRORS: {
    // Authorization endpoint errors
    INVALID_REQUEST: 'invalid_request',
    UNAUTHORIZED_CLIENT: 'unauthorized_client',
    ACCESS_DENIED: 'access_denied',
    UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
    INVALID_SCOPE: 'invalid_scope',
    SERVER_ERROR: 'server_error',
    TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',

    // Token endpoint errors
    INVALID_CLIENT: 'invalid_client',
    INVALID_GRANT: 'invalid_grant',
    UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',

    // Additional security errors
    INVALID_TOKEN: 'invalid_token',
    INSUFFICIENT_SCOPE: 'insufficient_scope',
  } as const,
  // OAuth2 Error Description 상수들
  ERROR_DESCRIPTIONS: {
    INVALID_REQUEST:
      'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
    UNAUTHORIZED_CLIENT:
      'The client is not authorized to request an authorization code using this method.',
    ACCESS_DENIED:
      'The resource owner or authorization server denied the request.',
    UNSUPPORTED_RESPONSE_TYPE:
      'The authorization server does not support obtaining an authorization code using this method.',
    INVALID_SCOPE: 'The requested scope is invalid, unknown, or malformed.',
    SERVER_ERROR:
      'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
    TEMPORARILY_UNAVAILABLE:
      'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
    INVALID_CLIENT:
      'Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).',
    INVALID_GRANT:
      'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.',
    UNSUPPORTED_GRANT_TYPE:
      'The authorization grant type is not supported by the authorization server.',
    INVALID_TOKEN:
      'The access token provided is expired, revoked, malformed, or invalid for other reasons.',
    INSUFFICIENT_SCOPE:
      'The request requires higher privileges than provided by the access token.',
  } as const,
  // OAuth2 파라미터 제한
  PKCE_METHODS: ['plain', 'S256'] as const,
  CODE_CHALLENGE_S256_LENGTH: 43,
  CODE_CHALLENGE_PLAIN_MIN_LENGTH: 43,
  CODE_CHALLENGE_PLAIN_MAX_LENGTH: 128,
  STATE_MAX_LENGTH: 256,
  REDIRECT_URI_MAX_LENGTH: 2048,
  CLIENT_ID_MAX_LENGTH: 100,
  SCOPE_MAX_LENGTH: 500,
  CODE_VERIFIER_MAX_LENGTH: 128,
  AUTHORIZATION_CODE_MAX_LENGTH: 100,
  REFRESH_TOKEN_MAX_LENGTH: 500,
  NONCE_MAX_LENGTH: 256,
  // 정규표현식 패턴
  PKCE_UNRESERVED_CHAR_PATTERN: /^[A-Za-z0-9_~-]+$/,
  CODE_CHALLENGE_S256_PATTERN: /^[A-Za-z0-9_-]{43}$/,
} as const;

// Rate limiting 상수들
export const RATE_LIMIT_CONSTANTS = {
  WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  MAX_REQUESTS: 100, // 100 requests per window
  MAX_TOKEN_REQUESTS: 10, // 10 token requests per window
} as const;

// OAuth2 에러 메시지들
export const OAUTH2_ERROR_MESSAGES = {
  INVALID_CLIENT_ID: '잘못된 client_id 파라미터입니다',
  INVALID_REDIRECT_URI: '잘못된 redirect_uri 파라미터입니다',
  INVALID_RESPONSE_TYPE: '잘못된 response_type 파라미터입니다',
  STATE_REQUIRED: '보안을 위해 state 파라미터가 필요합니다',
  UNSUPPORTED_RESPONSE_TYPE: '지원하지 않는 응답 타입입니다',
  INVALID_CLIENT: '잘못된 client_id입니다',
  INVALID_REDIRECT_URI_FORMAT: '잘못된 redirect_uri 형식입니다',
  INVALID_REDIRECT_URI_CLIENT: '이 클라이언트에 대한 잘못된 redirect_uri입니다',
  INVALID_SCOPE: '잘못된 scope 파라미터입니다',
  PKCE_CHALLENGE_MISSING:
    'code_challenge_method이 제공되었지만 code_challenge가 누락되었습니다',
  PKCE_METHOD_MISSING:
    'code_challenge가 제공되었지만 code_challenge_method가 누락되었습니다',
  INVALID_PKCE_METHOD: '잘못된 code_challenge_method입니다',
  INVALID_PKCE_FORMAT_S256: 'S256 방식에 대한 잘못된 code_challenge 형식입니다',
  INVALID_PKCE_LENGTH_PLAIN:
    'plain 방식에 대한 잘못된 code_challenge 길이입니다',
  RATE_LIMIT_EXCEEDED: '요청 제한을 초과했습니다. 잠시 후 다시 시도해주세요.',
  TOKEN_RATE_LIMIT_EXCEEDED:
    '토큰 요청 제한을 초과했습니다. 잠시 후 다시 시도해주세요.',
  INVALID_GRANT_TYPE: '잘못된 grant_type 파라미터입니다',
  UNSUPPORTED_GRANT_TYPE: '지원하지 않는 grant type입니다',
  INVALID_CODE: '잘못된 code 파라미터입니다',
  INVALID_AUTH_CODE: '잘못된 인증 코드입니다',
  INVALID_REFRESH_TOKEN: '잘못된 refresh_token 파라미터입니다',
  INVALID_TOKEN: '잘못된 refresh token입니다',
  USER_NOT_FOUND: '사용자를 찾을 수 없습니다',
  INVALID_CLIENT_CREDENTIALS: '잘못된 클라이언트 인증 정보입니다',
  PKCE_VERIFIER_REQUIRED: '이 인증 코드에 대해 PKCE code_verifier가 필요합니다',
  PKCE_PARAMS_MISSING: 'PKCE 파라미터가 필요하지만 누락되었습니다',
  PKCE_VERIFICATION_FAILED_PLAIN:
    'PKCE 검증 실패: code verifier가 code challenge와 일치하지 않습니다 (plain 방식)',
  PKCE_VERIFICATION_FAILED_S256:
    'PKCE 검증 실패: code verifier 해시가 code challenge와 일치하지 않습니다 (S256 방식)',
  UNSUPPORTED_PKCE_METHOD: '지원하지 않는 code challenge 방식입니다',
  PKCE_PARAMETERS_MISMATCH:
    'PKCE 파라미터 불일치: code_challenge와 code_challenge_method가 함께 제공되어야 합니다',
  OPENID_SCOPE_REQUIRED: 'openid scope가 필요합니다',
  INVALID_PKCE_LENGTH_S256: 'S256 방식에 대한 잘못된 code_challenge 길이입니다',
} as const;

// OAuth2 로그 메시지들
export const OAUTH2_LOG_MESSAGES = {
  REFRESH_TOKEN_REQUEST: '클라이언트로부터 refresh token 요청',
  REFRESH_TOKEN_SUCCESS: '클라이언트에 대한 refresh token이 성공적으로 갱신됨',
  INVALID_REFRESH_TOKEN: '클라이언트로부터 잘못된 refresh token 시도',
} as const;

// OAuth2 스코프 상수들
export const OAUTH2_SCOPES = {
  // OpenID Connect
  OPENID: 'openid',
  PROFILE: 'profile',
  EMAIL: 'email',
} as const;

// 스코프 설명
export const SCOPE_DESCRIPTIONS = {
  [OAUTH2_SCOPES.EMAIL]: '사용자 이메일 주소 읽기',
  [OAUTH2_SCOPES.OPENID]: 'OpenID Connect 인증 및 기본 프로필 정보 읽기',
  [OAUTH2_SCOPES.PROFILE]:
    '사용자 프로필 정보 읽기 (이름, 생년월일, 지역, 사진 등)',
} as const;

// 기본 스코프 목록 (OpenID Connect 표준)
export const DEFAULT_SCOPES = [
  OAUTH2_SCOPES.OPENID,
  OAUTH2_SCOPES.PROFILE,
] as const;

// 토큰 취소 사유 상수들
export const TOKEN_REVOCATION_REASONS = {
  // 사용자 액션
  USER_REVOKED_CONNECTION: 'user_revoked_connection',
  USER_REVOKED_TOKENS: 'user_revoked_tokens',
  USER_ACCOUNT_DELETED: 'user_account_deleted',
  USER_REVOKED: 'user_revoked',
  USER_LOGOUT: 'user_logout',

  // 관리자 액션
  ADMIN_REVOKED: 'admin_revoked',
  ADMIN_SUSPENDED: 'admin_suspended',

  // 보안 관련
  SECURITY_BREACH: 'security_breach',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  TOKEN_COMPROMISED: 'token_compromised',

  // 시스템 액션
  TOKEN_EXPIRED: 'token_expired',
  REFRESH_FAILED: 'refresh_failed',
  CLIENT_DEACTIVATED: 'client_deactivated',

  // 기타
  MAINTENANCE: 'maintenance',
  POLICY_VIOLATION: 'policy_violation',
} as const;

// 토큰 취소 사유 설명
export const TOKEN_REVOCATION_REASON_DESCRIPTIONS = {
  [TOKEN_REVOCATION_REASONS.USER_REVOKED_CONNECTION]: '사용자가 연결을 해제함',
  [TOKEN_REVOCATION_REASONS.USER_LOGOUT]: '사용자 로그아웃',
  [TOKEN_REVOCATION_REASONS.USER_ACCOUNT_DELETED]: '사용자 계정 삭제',
  [TOKEN_REVOCATION_REASONS.ADMIN_REVOKED]: '관리자에 의해 취소됨',
  [TOKEN_REVOCATION_REASONS.ADMIN_SUSPENDED]: '관리자에 의해 일시 정지됨',
  [TOKEN_REVOCATION_REASONS.SECURITY_BREACH]: '보안 침해 감지',
  [TOKEN_REVOCATION_REASONS.SUSPICIOUS_ACTIVITY]: '의심스러운 활동 감지',
  [TOKEN_REVOCATION_REASONS.TOKEN_COMPROMISED]: '토큰이 유출됨',
  [TOKEN_REVOCATION_REASONS.TOKEN_EXPIRED]: '토큰 만료',
  [TOKEN_REVOCATION_REASONS.REFRESH_FAILED]: '토큰 갱신 실패',
  [TOKEN_REVOCATION_REASONS.CLIENT_DEACTIVATED]: '클라이언트 비활성화',
  [TOKEN_REVOCATION_REASONS.MAINTENANCE]: '시스템 유지보수',
  [TOKEN_REVOCATION_REASONS.POLICY_VIOLATION]: '정책 위반',
} as const;

// 감사 로그 리소스 타입 상수들
export const AUDIT_LOG_RESOURCE_TYPES = {
  // OAuth2 관련
  TOKEN: 'token',
  CLIENT: 'client',
  CLIENT_CONNECTION: 'client_connection',
  USER: 'user',

  // 시스템 관련
  SYSTEM: 'system',
  CONFIGURATION: 'configuration',

  // 기타
  OTHER: 'other',
} as const;

// 액티비티 타입 상수들 (대시보드 최근 활동용)
export const ACTIVITY_TYPES = {
  // 사용자 관련
  ACCOUNT_CREATED: 'account_created',
  LOGIN: 'login',

  // 클라이언트 관련
  CLIENT_CREATED: 'client_created',
  CLIENT_UPDATED: 'client_updated',

  // 토큰 관련
  TOKEN_CREATED: 'token_created',
  TOKEN_REVOKED: 'token_revoked',
} as const;
