// OAuth2 관련 상수들
export const OAUTH2_CONSTANTS = {
  SUPPORTED_RESPONSE_TYPE: 'code',
  SUPPORTED_GRANT_TYPES: [
    'authorization_code',
    'refresh_token',
    'client_credentials',
  ] as const,
  PKCE_METHODS: ['plain', 'S256'] as const,
  CODE_CHALLENGE_S256_LENGTH: 43,
  CODE_CHALLENGE_PLAIN_MIN_LENGTH: 43,
  CODE_CHALLENGE_PLAIN_MAX_LENGTH: 128,
  // 추가된 길이 제한 상수들
  STATE_MAX_LENGTH: 256,
  REDIRECT_URI_MAX_LENGTH: 2048,
  CLIENT_ID_MAX_LENGTH: 100,
  SCOPE_MAX_LENGTH: 500,
  CODE_VERIFIER_MAX_LENGTH: 128,
  AUTHORIZATION_CODE_MAX_LENGTH: 100,
  REFRESH_TOKEN_MAX_LENGTH: 500,
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
  INVALID_CLIENT_ID: 'Invalid client_id parameter',
  INVALID_REDIRECT_URI: 'Invalid redirect_uri parameter',
  INVALID_RESPONSE_TYPE: 'Invalid response_type parameter',
  STATE_REQUIRED: 'state parameter is required for security',
  UNSUPPORTED_RESPONSE_TYPE: 'Unsupported response type',
  INVALID_CLIENT: 'Invalid client_id',
  INVALID_REDIRECT_URI_FORMAT: 'Invalid redirect_uri format',
  INVALID_REDIRECT_URI_CLIENT: 'Invalid redirect_uri for this client',
  INVALID_SCOPE: 'Invalid scope parameter',
  PKCE_CHALLENGE_MISSING:
    'code_challenge_method is provided but code_challenge is missing',
  PKCE_METHOD_MISSING:
    'code_challenge is provided but code_challenge_method is missing',
  INVALID_PKCE_METHOD: 'Invalid code_challenge_method',
  INVALID_PKCE_FORMAT_S256: 'Invalid code_challenge format for S256 method',
  INVALID_PKCE_LENGTH_PLAIN: 'Invalid code_challenge length for plain method',
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded. Please try again later.',
  TOKEN_RATE_LIMIT_EXCEEDED:
    'Token request rate limit exceeded. Please try again later.',
  INVALID_GRANT_TYPE: 'Invalid grant_type parameter',
  UNSUPPORTED_GRANT_TYPE: 'Unsupported grant type',
  INVALID_CODE: 'Invalid code parameter',
  INVALID_AUTH_CODE: 'Invalid authorization code',
  INVALID_REFRESH_TOKEN: 'Invalid refresh_token parameter',
  INVALID_TOKEN: 'Invalid refresh token',
  USER_NOT_FOUND: 'User not found',
  INVALID_CLIENT_CREDENTIALS: 'Invalid client credentials',
  PKCE_VERIFIER_REQUIRED:
    'PKCE code_verifier is required for this authorization code',
  PKCE_PARAMS_MISSING: 'PKCE parameters are required but missing',
  PKCE_VERIFICATION_FAILED_PLAIN:
    'PKCE verification failed: code verifier does not match code challenge (plain method)',
  PKCE_VERIFICATION_FAILED_S256:
    'PKCE verification failed: code verifier hash does not match code challenge (S256 method)',
  UNSUPPORTED_PKCE_METHOD: 'Unsupported code challenge method',
} as const;

// OAuth2 로그 메시지들
export const OAUTH2_LOG_MESSAGES = {
  REFRESH_TOKEN_REQUEST: 'Refresh token request from client',
  REFRESH_TOKEN_SUCCESS: 'Refresh token successfully renewed for client',
  INVALID_REFRESH_TOKEN: 'Invalid refresh token attempt from client',
} as const;

// OAuth2 스코프 상수들
export const OAUTH2_SCOPES = {
  // 사용자 정보 관련
  READ_USER: 'read:user',
  WRITE_USER: 'write:user',
  DELETE_USER: 'delete:user',

  // 프로필 관련
  READ_PROFILE: 'read:profile',
  WRITE_PROFILE: 'write:profile',

  // 파일 업로드 관련
  UPLOAD_FILE: 'upload:file',
  READ_FILE: 'read:file',
  DELETE_FILE: 'delete:file',

  // 클라이언트 관리 관련
  READ_CLIENT: 'read:client',
  WRITE_CLIENT: 'write:client',
  DELETE_CLIENT: 'delete:client',

  // 관리자 관련
  ADMIN: 'admin',

  // 기본 스코프
  BASIC: 'basic',
} as const;

// 스코프 설명
export const SCOPE_DESCRIPTIONS = {
  [OAUTH2_SCOPES.READ_USER]: '사용자 기본 정보 읽기',
  [OAUTH2_SCOPES.WRITE_USER]: '사용자 정보 수정',
  [OAUTH2_SCOPES.DELETE_USER]: '사용자 삭제',
  [OAUTH2_SCOPES.READ_PROFILE]: '사용자 프로필 읽기',
  [OAUTH2_SCOPES.WRITE_PROFILE]: '사용자 프로필 수정',
  [OAUTH2_SCOPES.UPLOAD_FILE]: '파일 업로드',
  [OAUTH2_SCOPES.READ_FILE]: '파일 읽기',
  [OAUTH2_SCOPES.DELETE_FILE]: '파일 삭제',
  [OAUTH2_SCOPES.READ_CLIENT]: '클라이언트 정보 읽기',
  [OAUTH2_SCOPES.WRITE_CLIENT]: '클라이언트 정보 수정',
  [OAUTH2_SCOPES.DELETE_CLIENT]: '클라이언트 삭제',
  [OAUTH2_SCOPES.ADMIN]: '관리자 권한',
  [OAUTH2_SCOPES.BASIC]: '기본 접근 권한',
} as const;

// 기본 스코프 목록
export const DEFAULT_SCOPES = [
  OAUTH2_SCOPES.BASIC,
  OAUTH2_SCOPES.READ_USER,
] as const;
