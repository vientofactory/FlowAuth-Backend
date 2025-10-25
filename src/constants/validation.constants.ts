/**
 * 검증 관련 상수 정의
 */
export const VALIDATION_CONSTANTS = {
  EMAIL: {
    REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    MAX_LENGTH: 255,
    ERROR_MESSAGES: {
      INVALID_FORMAT: '올바른 이메일 형식이 아닙니다.',
      REQUIRED: '이메일을 입력해주세요.',
      ALREADY_EXISTS: '이미 사용중인 이메일입니다.',
      AVAILABLE: '사용 가능한 이메일입니다.',
    },
  },
  USERNAME: {
    REGEX: /^[a-zA-Z0-9_]+$/,
    MIN_LENGTH: 3,
    MAX_LENGTH: 100,
    ERROR_MESSAGES: {
      INVALID_FORMAT: '사용자명은 영문, 숫자, 언더스코어만 사용할 수 있습니다.',
      TOO_SHORT: '사용자명은 최소 3자 이상이어야 합니다.',
      TOO_LONG: '사용자명은 최대 100자까지 가능합니다.',
      REQUIRED: '사용자명을 입력해주세요.',
      ALREADY_EXISTS: '이미 사용중인 사용자명입니다.',
      AVAILABLE: '사용 가능한 사용자명입니다.',
    },
  },
  PROFILE_USERNAME: {
    REGEX: /^[a-zA-Z0-9_-]+$/,
    MIN_LENGTH: 3,
    MAX_LENGTH: 100,
    ERROR_MESSAGES: {
      INVALID_FORMAT:
        '사용자명은 영문, 숫자, 하이픈, 언더스코어만 사용할 수 있습니다.',
      TOO_SHORT: '사용자명은 최소 3자 이상이어야 합니다.',
      TOO_LONG: '사용자명은 최대 100자까지 가능합니다.',
      REQUIRED: '사용자명을 입력해주세요.',
      ALREADY_EXISTS: '이미 사용중인 사용자명입니다.',
      AVAILABLE: '사용 가능한 사용자명입니다.',
    },
  },
  NAME: {
    REGEX: /^[a-zA-Z가-힣\s\-.']+$/,
    MAX_LENGTH: 100,
    ERROR_MESSAGES: {
      INVALID_FORMAT:
        '이름은 한글, 영문, 공백, 하이픈, 점, 아포스트로피만 사용할 수 있습니다.',
      REQUIRED: '이름은 비어있을 수 없습니다.',
      TOO_LONG: '이름은 최대 100자까지 가능합니다.',
    },
  },
  TWO_FACTOR_TOKEN: {
    REGEX: /^\d{6}$/,
    ERROR_MESSAGES: {
      INVALID_FORMAT: '2FA 토큰은 6자리 숫자여야 합니다.',
      REQUIRED: '2FA 토큰이 필요합니다.',
    },
  },
  BACKUP_CODE: {
    REGEX: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/,
    ERROR_MESSAGES: {
      INVALID_FORMAT: '백업 코드는 XXXX-XXXX 형식이어야 합니다.',
      REQUIRED: '백업 코드가 필요합니다.',
    },
  },
  AUTHORIZATION: {
    BEARER_PREFIX: 'Bearer ',
    ERROR_MESSAGES: {
      HEADER_REQUIRED: 'Authorization 헤더가 필요합니다.',
      INVALID_FORMAT: '잘못된 Authorization 헤더 형식입니다.',
      BEARER_REQUIRED: 'Bearer 토큰 형식이 필요합니다.',
      TOKEN_EMPTY: '토큰 값이 비어있습니다.',
    },
  },
  GENERAL: {
    ERROR_MESSAGES: {
      INVALID_ID: 'Invalid ID parameter',
      UNAUTHENTICATED: '인증되지 않은 요청입니다.',
      UPDATE_DATA_REQUIRED: '업데이트 데이터가 필요합니다.',
    },
  },
} as const;

// 암호화 관련 검증 상수
export const CRYPTO_VALIDATION = {
  // Base64URL 인코딩 검증 (A-Z, a-z, 0-9, -, _ 만 허용)
  BASE64URL_REGEX: /^[A-Za-z0-9_-]+$/,

  // Base64URL 패턴 에러 메시지
  BASE64URL_ERROR_MESSAGE: 'Invalid base64url format',
} as const;

// 비밀번호 검증 상수
export const PASSWORD_VALIDATION = {
  // 최소 길이
  MIN_LENGTH: 8,

  // 소문자 포함 패턴
  LOWERCASE_PATTERN: /(?=.*[a-z])/,

  // 대문자 포함 패턴
  UPPERCASE_PATTERN: /(?=.*[A-Z])/,

  // 숫자 포함 패턴
  DIGIT_PATTERN: /(?=.*\d)/,

  // 에러 메시지들
  ERRORS: {
    TOO_SHORT: 'Password must be at least 8 characters long',
    NO_LOWERCASE: 'Password must contain at least one lowercase letter',
    NO_UPPERCASE: 'Password must contain at least one uppercase letter',
    NO_DIGIT: 'Password must contain at least one number',
  },
} as const;

/**
 * 가용성 체크 결과 타입
 */
export interface AvailabilityResult {
  available: boolean;
  message: string;
}

/**
 * URL 검증 옵션
 */
export interface UrlValidationOptions {
  allowedProtocols?: string[];
  requireHttps?: boolean;
}
