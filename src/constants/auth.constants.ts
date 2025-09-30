// JWT 관련 상수들
export const JWT_CONSTANTS = {
  SECRET_KEY_FALLBACK: 'your-secret-key', // fallback value, use ConfigService.get('JWT_SECRET') in actual usage
  EXPIRES_IN: '1h',
  ALGORITHMS: ['HS256'] as const,
  TOKEN_TYPE: 'access' as const,
} as const;

// 토큰 타입 상수들
export const TOKEN_TYPES = {
  LOGIN: 'login',
  OAUTH2: 'oauth2',
} as const;

export type TokenType = (typeof TOKEN_TYPES)[keyof typeof TOKEN_TYPES];

// 권한 비트마스크 상수들
export const PERMISSIONS = {
  // 사용자 권한
  READ_USER: 1 << 0, // 1
  WRITE_USER: 1 << 1, // 2
  DELETE_USER: 1 << 2, // 4

  // 클라이언트 권한
  READ_CLIENT: 1 << 3, // 8
  WRITE_CLIENT: 1 << 4, // 16
  DELETE_CLIENT: 1 << 5, // 32

  // 토큰 권한
  READ_TOKEN: 1 << 6, // 64
  WRITE_TOKEN: 1 << 7, // 128
  DELETE_TOKEN: 1 << 8, // 256

  // 시스템 권한
  MANAGE_USERS: 1 << 9, // 512
  MANAGE_SYSTEM: 1 << 10, // 1024

  // 대시보드 권한
  READ_DASHBOARD: 1 << 11, // 2048
  WRITE_DASHBOARD: 1 << 12, // 4096
  MANAGE_DASHBOARD: 1 << 13, // 8192

  // 업로드 권한
  UPLOAD_FILE: 1 << 14, // 16384

  // ADMIN 권한 - 별도의 슈퍼 권한
  ADMIN_ACCESS: 1 << 31, // 2147483648
} as const;

// 권한 헬퍼 함수들
export const PERMISSION_UTILS = {
  /**
   * 모든 권한의 비트마스크를 계산 (ADMIN_ACCESS 제외)
   */
  getAllPermissionsMask: (): number => {
    return Object.values(PERMISSIONS).reduce((acc, perm) => {
      if (perm !== PERMISSIONS.ADMIN_ACCESS) {
        return acc | perm;
      }
      return acc;
    }, 0);
  },

  /**
   * ADMIN 권한 값 (ADMIN_ACCESS 비트만)
   */
  getAdminPermission: (): number => {
    return PERMISSIONS.ADMIN_ACCESS;
  },

  /**
   * 사용 가능한 모든 권한 목록 (ADMIN_ACCESS 제외)
   */
  getAllPermissions: () => {
    return Object.values(PERMISSIONS).filter((p) => {
      return p !== PERMISSIONS.ADMIN_ACCESS;
    });
  },

  /**
   * 권한 이름으로 값 찾기
   */
  getPermissionValue: (name: keyof typeof PERMISSIONS) => PERMISSIONS[name],
} as const;

// 역할 상수들
export const ROLES = {
  USER: 'user',
  CLIENT_MANAGER: 'client_manager',
  TOKEN_MANAGER: 'token_manager',
  USER_MANAGER: 'user_manager',
  ADMIN: 'admin',
} as const;

// 역할별 권한 매핑
export const ROLE_PERMISSIONS = {
  [ROLES.USER]: [PERMISSIONS.READ_USER, PERMISSIONS.READ_DASHBOARD],
  [ROLES.CLIENT_MANAGER]: [
    PERMISSIONS.READ_CLIENT,
    PERMISSIONS.WRITE_CLIENT,
    PERMISSIONS.DELETE_CLIENT,
    PERMISSIONS.READ_TOKEN,
    PERMISSIONS.WRITE_TOKEN,
    PERMISSIONS.DELETE_TOKEN,
    PERMISSIONS.READ_DASHBOARD,
    PERMISSIONS.WRITE_DASHBOARD,
    PERMISSIONS.UPLOAD_FILE,
  ],
  [ROLES.TOKEN_MANAGER]: [
    PERMISSIONS.READ_TOKEN,
    PERMISSIONS.WRITE_TOKEN,
    PERMISSIONS.DELETE_TOKEN,
  ],
  [ROLES.USER_MANAGER]: [
    PERMISSIONS.READ_USER,
    PERMISSIONS.WRITE_USER,
    PERMISSIONS.DELETE_USER,
    PERMISSIONS.MANAGE_USERS,
  ],
  [ROLES.ADMIN]: [PERMISSIONS.ADMIN_ACCESS], // ADMIN은 별도의 슈퍼 권한만 가짐
} as const;

// 역할 계층 구조 (상속 관계)
export const ROLE_HIERARCHY = {
  [ROLES.USER]: [],
  [ROLES.CLIENT_MANAGER]: [ROLES.USER],
  [ROLES.TOKEN_MANAGER]: [ROLES.USER],
  [ROLES.USER_MANAGER]: [ROLES.USER, ROLES.CLIENT_MANAGER],
  [ROLES.ADMIN]: [
    ROLES.USER,
    ROLES.CLIENT_MANAGER,
    ROLES.TOKEN_MANAGER,
    ROLES.USER_MANAGER,
  ],
} as const;

// 역할 이름 매핑
export const ROLE_NAMES = {
  [ROLES.USER]: '일반 사용자',
  [ROLES.CLIENT_MANAGER]: '클라이언트 관리자',
  [ROLES.TOKEN_MANAGER]: '토큰 관리자',
  [ROLES.USER_MANAGER]: '사용자 관리자',
  [ROLES.ADMIN]: '시스템 관리자',
} as const;

// JWT 토큰 만료 시간 상수들 (시간 단위)
export const JWT_TOKEN_EXPIRY = {
  LOGIN_HOURS: 24, // 로그인 토큰: 24시간
  OAUTH2_HOURS: 1, // OAuth2 토큰: 1시간
} as const;

// 인증 관련 상수들
export const AUTH_CONSTANTS = {
  BCRYPT_SALT_ROUNDS: 10,
  DEFAULT_USER_PERMISSIONS: ROLES.CLIENT_MANAGER, // OAuth2 기본 기능 권한
  TOKEN_EXPIRATION_SECONDS: 86400, // 24 hours (로그인 토큰과 일치)
  TOKEN_TYPE: 'access' as const,
} as const;

// 에러 메시지들
export const AUTH_ERROR_MESSAGES = {
  JWT_SECRET_MISSING: 'JWT_SECRET 환경 변수가 필요합니다',
  INVALID_CREDENTIALS: '잘못된 자격 증명입니다',
  USER_NOT_FOUND: '사용자를 찾을 수 없습니다',
  TOKEN_EXPIRED: '토큰이 만료되었습니다',
  INVALID_TOKEN: '잘못된 토큰입니다',
  INVALID_TOKEN_TYPE: '잘못된 토큰 유형입니다',
  UNAUTHORIZED: '권한이 없습니다',
  AUTHENTICATION_FAILED: '인증에 실패했습니다',
  USER_ALREADY_EXISTS: '이미 존재하는 사용자입니다',
  LOGIN_FAILED: '로그인에 실패했습니다',
  TWO_FACTOR_NOT_ENABLED: '이 사용자에 대해 2단계 인증이 활성화되지 않았습니다',
  INVALID_TWO_FACTOR_TOKEN: '잘못된 2단계 인증 토큰입니다',
  INVALID_BACKUP_CODE: '잘못된 백업 코드입니다',
} as const;

// 로그 메시지들
export const AUTH_LOG_MESSAGES = {
  JWT_STRATEGY_INITIALIZED:
    'JWT Strategy initialized with Bearer token extraction',
  LOGIN_ATTEMPT: 'Login attempt for email:',
  LOGIN_SUCCESSFUL: 'Login successful for user:',
  LOGIN_FAILED_USER_NOT_FOUND: 'Login failed: User not found for email:',
  LOGIN_FAILED_INVALID_PASSWORD: 'Login failed: Invalid password for user:',
  JWT_VALIDATION_SUCCESSFUL: 'JWT validation successful for user:',
  JWT_VALIDATION_ERROR: 'JWT validation error:',
  PROFILE_REQUEST: 'Profile request for user ID:',
  PROFILE_RETRIEVAL_SUCCESSFUL: 'Profile retrieved for user:',
  PROFILE_RETRIEVAL_FAILED: 'Profile retrieval failed for user ID:',
  INVALID_JWT_PAYLOAD_SUB: 'Invalid JWT payload: missing or invalid sub claim',
  LOGIN_FAILED: 'Login error for email',
  INVALID_JWT_PAYLOAD_EMAIL:
    'Invalid JWT payload: missing or invalid email claim',
  INVALID_TOKEN_TYPE: 'Invalid token type:',
  USER_NOT_FOUND_BY_ID: 'User not found for ID:',
  EMAIL_MISMATCH: 'Email mismatch for user ID:',
} as const;

// 사용자 유형 정의
export enum USER_TYPES {
  REGULAR = 'regular', // 일반 사용자 - OAuth2 로그인만 사용
  DEVELOPER = 'developer', // 개발자 - 클라이언트 관리 가능
}

// 캐시 관련 상수들
export const CACHE_CONSTANTS = {
  USER_CACHE_TTL: 600000, // 10분 (밀리초)
  PERMISSIONS_CACHE_TTL: 300000, // 5분 (밀리초)
} as const;

// 2FA 관련 상수들
export const TWO_FACTOR_CONSTANTS = {
  SECRET_LENGTH: 32, // TOTP 시크릿 길이
  BACKUP_CODE_COUNT: 10, // 백업 코드 개수
  BACKUP_CODE_LENGTH: 10, // 각 백업 코드 길이
  WINDOW_TIME: 30, // TOTP 윈도우 시간 (초)
} as const;

// 사용자 유형별 기본 권한 (역할 기반)
export const USER_TYPE_PERMISSIONS = {
  [USER_TYPES.REGULAR]: ROLE_PERMISSIONS[ROLES.USER].reduce(
    (acc, perm) => acc | perm,
    0,
  ),
  [USER_TYPES.DEVELOPER]: ROLE_PERMISSIONS[ROLES.CLIENT_MANAGER].reduce(
    (acc, perm) => acc | perm,
    0,
  ),
} as const;
