// JWT 관련 상수들
export const JWT_CONSTANTS = {
  SECRET_KEY_FALLBACK: 'your-secret-key', // fallback value, use ConfigService.get('JWT_SECRET') in actual usage
  EXPIRES_IN: '1h',
  ALGORITHMS: ['HS256'] as const,
  TOKEN_TYPE: 'access' as const,
} as const;

// 인증 관련 상수들
export const AUTH_CONSTANTS = {
  BCRYPT_SALT_ROUNDS: 10,
  DEFAULT_USER_ROLES: ['user'] as const,
  TOKEN_EXPIRATION_SECONDS: 3600, // 1 hour
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
