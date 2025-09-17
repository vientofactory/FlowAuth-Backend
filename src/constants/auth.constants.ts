// JWT 관련 상수들
export const JWT_CONSTANTS = {
  SECRET_KEY_FALLBACK: 'your-secret-key', // fallback value, use ConfigService.get('JWT_SECRET') in actual usage
  EXPIRES_IN: '1h',
  ALGORITHMS: ['HS256'] as const,
  TOKEN_TYPE: 'access' as const,
} as const;

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
  // ADMIN 권한은 별도로 계산됨 (모든 권한의 조합)
} as const;

// 권한 헬퍼 함수들
export const PERMISSION_UTILS = {
  /**
   * 모든 권한의 비트마스크를 계산
   */
  getAllPermissionsMask: (): number => {
    return Object.values(PERMISSIONS).reduce((acc, perm) => acc | perm, 0);
  },

  /**
   * ADMIN 권한 값 (모든 권한의 조합)
   */
  getAdminPermission: (): number => {
    return PERMISSION_UTILS.getAllPermissionsMask();
  },

  /**
   * 사용 가능한 모든 권한 목록
   */
  getAllPermissions: () => Object.values(PERMISSIONS),

  /**
   * 권한 이름으로 값 찾기
   */
  getPermissionValue: (name: keyof typeof PERMISSIONS) => PERMISSIONS[name],
} as const;

// 사전 정의된 역할들
export const ROLES = {
  USER: PERMISSIONS.READ_USER,
  CLIENT_MANAGER:
    PERMISSIONS.READ_CLIENT |
    PERMISSIONS.WRITE_CLIENT |
    PERMISSIONS.DELETE_CLIENT |
    PERMISSIONS.READ_TOKEN |
    PERMISSIONS.WRITE_TOKEN |
    PERMISSIONS.DELETE_TOKEN, // OAuth2 기본 기능 포함
  TOKEN_MANAGER:
    PERMISSIONS.READ_TOKEN | PERMISSIONS.WRITE_TOKEN | PERMISSIONS.DELETE_TOKEN,
  USER_MANAGER:
    PERMISSIONS.READ_USER |
    PERMISSIONS.WRITE_USER |
    PERMISSIONS.DELETE_USER |
    PERMISSIONS.MANAGE_USERS,
  ADMIN: PERMISSION_UTILS.getAdminPermission(), // 동적으로 계산된 모든 권한
} as const;

// 역할 이름 매핑
export const ROLE_NAMES = {
  [ROLES.USER]: '일반 사용자',
  [ROLES.CLIENT_MANAGER]: '클라이언트 관리자',
  [ROLES.TOKEN_MANAGER]: '토큰 관리자',
  [ROLES.USER_MANAGER]: '사용자 관리자',
  [ROLES.ADMIN]: '시스템 관리자',
} as const;

// 인증 관련 상수들
export const AUTH_CONSTANTS = {
  BCRYPT_SALT_ROUNDS: 10,
  DEFAULT_USER_PERMISSIONS: ROLES.CLIENT_MANAGER, // OAuth2 기본 기능 권한
  TOKEN_EXPIRATION_SECONDS: 86400, // 24 hours
  TOKEN_TYPE: 'access' as const,
} as const;

// 에러 메시지들
export const AUTH_ERROR_MESSAGES = {
  JWT_SECRET_MISSING: 'JWT_SECRET environment variable is required',
  INVALID_CREDENTIALS: 'Invalid credentials',
  USER_NOT_FOUND: 'User not found',
  TOKEN_EXPIRED: 'Token has expired',
  INVALID_TOKEN: 'Invalid token',
  INVALID_TOKEN_TYPE: 'Invalid token type',
  UNAUTHORIZED: 'Unauthorized',
  AUTHENTICATION_FAILED: 'Authentication failed',
  USER_ALREADY_EXISTS: 'User already exists',
  LOGIN_FAILED: 'Login failed',
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
