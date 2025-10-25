/**
 * 대시보드 관련 상수 및 설정
 */
export const DASHBOARD_CONFIG = {
  // 캐시 설정
  CACHE: {
    TTL: 120000, // 2분 (밀리초)
    KEY_PREFIX: {
      STATS: 'stats',
      ACTIVITIES: 'activities',
      USER: 'user',
      PERMISSIONS: 'permissions',
    },
  },

  // 분석 임계값
  ANALYTICS: {
    THRESHOLDS: {
      EXPIRATION_RATE_WARNING: 20, // 20%
      TREND_ANALYSIS_DAYS: 7,
      HIGH_ACTIVITY_THRESHOLD: 50,
    },
  },

  // 통계 설정
  STATS: {
    TIME_RANGES: {
      TOKEN_ISSUANCE_HOURS: 24,
      TOKEN_ISSUANCE_DAYS: 30,
    },
    LIMITS: {
      CLIENT_USAGE_TOP: 10,
      SCOPE_USAGE_TOP: 10,
    },
    // 기본 스코프 목록 (동적 분석이 실패할 경우 폴백용)
    DEFAULT_SCOPES: ['read', 'write', 'profile', 'email', 'openid'],
  },

  // 쿼리 최적화 설정
  QUERY: {
    BATCH_SIZE: 100,
    TIMEOUT: 30000, // 30초
  },

  ACTIVITIES: {
    DEFAULT_LIMIT: 10,
    MAX_LIMIT: 50,
  },
} as const;

/**
 * 캐시 키 생성 헬퍼
 */
export const CACHE_KEYS = {
  stats: (userId: number) =>
    `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.STATS}:${userId}`,
  activities: (userId: number, limit: number) =>
    `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.ACTIVITIES}:${userId}:${limit}`,
  user: (userId: number) =>
    `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.USER}:${userId}`,
  permissions: (userId: number) =>
    `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.PERMISSIONS}:${userId}`,
  advancedStats: (userId: number, days: number) =>
    `advanced_stats:${userId}:${days}`,
} as const;
