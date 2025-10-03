// JWT 관련 상수들
export const JWT_CONSTANTS = {
  // 알고리즘
  ALGORITHMS: {
    RS256: 'RS256',
    HS256: 'HS256',
  } as const,

  // 키 ID들
  KEY_IDS: {
    RSA_ENV: 'rsa-key-env',
    RSA_DEV: 'rsa-key-dev',
  } as const,

  // 기본 시크릿 키 (개발 환경용)
  SECRET_KEY_FALLBACK: 'fallback-secret-key',

  // 토큰 만료 시간 (기본값)
  EXPIRES_IN: '1h',

  // JWKS 엔드포인트
  JWKS_PATH: '.well-known/jwks.json',
} as const;

// 캐시 관련 상수들
export const CACHE_CONSTANTS = {
  // 토큰 검증 캐시 시간 (5분)
  TOKEN_VALIDATION_TTL: 300000, // 5 minutes in milliseconds

  // JWKS 캐시 시간 (1시간)
  JWKS_TTL: 3600000, // 1 hour in milliseconds

  // 캐시 키 접두사
  KEY_PREFIXES: {
    TOKEN: 'token:',
    JWKS: 'jwks:',
  } as const,
} as const;

// 토큰 인트로스펙션 관련 상수들
export const TOKEN_INTROSPECTION_CONSTANTS = {
  // 토큰 상태
  TOKEN_STATUS: {
    ACTIVE: true,
    INACTIVE: false,
  } as const,

  // 토큰 타입
  TOKEN_TYPES: {
    ACCESS_TOKEN: 'access_token',
    ID_TOKEN: 'id_token',
    REFRESH_TOKEN: 'refresh_token',
  } as const,

  // 클레임 필드명들
  CLAIMS: {
    USERNAME: 'preferred_username',
    EMAIL_VERIFIED: 'email_verified',
    SUBJECT: 'sub',
    CLIENT_ID: 'client_id',
    SCOPE: 'scope',
    TOKEN_TYPE: 'token_type',
    EXPIRES_AT: 'exp',
    ISSUED_AT: 'iat',
  } as const,
} as const;
