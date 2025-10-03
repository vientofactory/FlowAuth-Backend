// OAuth2 관련 상수들
export const OAUTH2_CONSTANTS = {
  SUPPORTED_RESPONSE_TYPES: ['code', 'id_token', 'token id_token'] as const,
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
} as const;

// OAuth2 로그 메시지들
export const OAUTH2_LOG_MESSAGES = {
  REFRESH_TOKEN_REQUEST: '클라이언트로부터 refresh token 요청',
  REFRESH_TOKEN_SUCCESS: '클라이언트에 대한 refresh token이 성공적으로 갱신됨',
  INVALID_REFRESH_TOKEN: '클라이언트로부터 잘못된 refresh token 시도',
} as const;

// OAuth2 스코프 상수들
export const OAUTH2_SCOPES = {
  // 계정 기본 정보 스코프 (Discord 스타일)
  IDENTIFY: 'identify',

  // 이메일 주소 스코프
  EMAIL: 'email',
} as const;

// 스코프 설명
export const SCOPE_DESCRIPTIONS = {
  [OAUTH2_SCOPES.IDENTIFY]: '계정의 기본 정보 읽기 (사용자 ID, 이름 등)',
  [OAUTH2_SCOPES.EMAIL]: '사용자 이메일 주소 읽기',
} as const;

// 기본 스코프 목록
export const DEFAULT_SCOPES = [OAUTH2_SCOPES.IDENTIFY] as const;
