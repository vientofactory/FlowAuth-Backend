/**
 * HTTP 응답 관련 상수
 */
export const HTTP_RESPONSES = {
  SUCCESS: {
    USER_REGISTERED: '사용자가 성공적으로 등록됨',
    LOGIN_SUCCESS: '로그인 성공',
    LOGOUT_SUCCESS: 'Logged out successfully',
    TOKEN_REFRESHED: '토큰 리프래시 성공',
    CLIENT_CREATED: '클라이언트가 성공적으로 생성됨',
    CLIENT_UPDATED: '클라이언트 정보가 성공적으로 업데이트됨',
    CLIENT_STATUS_UPDATED: '클라이언트 상태가 성공적으로 업데이트됨',
    CLIENT_SECRET_RESET: '클라이언트 시크릿이 성공적으로 재설정됨',
    CLIENT_LOGO_REMOVED: '클라이언트 로고가 성공적으로 제거됨',
    CLIENT_DELETED: 'Client deleted successfully',
    TOKEN_REVOKED: 'Token revoked successfully',
    ALL_TOKENS_REVOKED: 'All user tokens revoked successfully',
    TOKENS_BY_TYPE_REVOKED: 'tokens revoked successfully',
    TWO_FACTOR_VERIFIED: '2FA 검증 성공 및 로그인 완료',
    BACKUP_CODE_VERIFIED: '백업 코드 검증 성공 및 로그인 완료',
  },
  ERROR: {
    INVALID_REQUEST: '잘못된 요청 데이터',
    UNAUTHORIZED: '인증 실패',
    FORBIDDEN: '권한이 없음',
    NOT_FOUND: '리소스를 찾을 수 없음',
    RATE_LIMITED: '요청 제한 초과',
    VALIDATION_FAILED: '입력 검증 실패',
    CLIENT_NOT_FOUND: '클라이언트를 찾을 수 없음',
    TOKEN_NOT_FOUND: '토큰을 찾을 수 없음',
    INVALID_TOKEN: '유효하지 않은 토큰',
    INVALID_2FA_TOKEN: '잘못된 2FA 토큰',
    INVALID_BACKUP_CODE: '잘못된 백업 코드',
    INVALID_TOKEN_TYPE: '잘못된 토큰 타입',
    ADMIN_PERMISSION_REQUIRED: '관리자 권한이 필요함',
    OWNERSHIP_REQUIRED: '소유권이 없음',
  },
} as const;

/**
 * API 태그 상수
 */
export const API_TAGS = {
  AUTHENTICATION: 'Authentication',
  CLIENT_MANAGEMENT: 'Client Management',
  TOKEN_MANAGEMENT: 'Token Management',
  TWO_FACTOR_AUTH: '2FA Management',
  USER_MANAGEMENT: 'User Management',
} as const;

/**
 * 권한 설명
 */
export const PERMISSION_DESCRIPTIONS = {
  READ_CLIENT: 'read:client',
  WRITE_CLIENT: 'write:client',
  DELETE_CLIENT: 'delete:client (관리자 전용)',
  READ_TOKEN: 'read:token',
  DELETE_TOKEN: 'delete:token',
} as const;
