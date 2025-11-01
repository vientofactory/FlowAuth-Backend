/**
 * 캐시 관련 상수 및 설정
 * 모든 서비스에서 사용하는 캐시 TTL 값들을 중앙 관리
 */
export const CACHE_CONFIG = {
  // 시간 단위 (밀리초)
  TIME_UNITS: {
    SECOND: 1000,
    MINUTE: 60 * 1000,
    HOUR: 60 * 60 * 1000,
    DAY: 24 * 60 * 60 * 1000,
  },

  // 캐시 TTL 값들
  TTL: {
    // 대시보드 관련
    DASHBOARD_STATS: 2 * 60 * 1000, // 2분
    DASHBOARD_ACTIVITIES: 2 * 60 * 1000, // 2분
    DASHBOARD_ADVANCED_STATS: 10 * 60 * 1000, // 10분

    // 프로필 관련
    USER_PROFILE: 10 * 60 * 1000, // 10분

    // OAuth2 관련
    SCOPES_ALL: 60 * 60 * 1000, // 1시간
    TOKEN_VALIDATION: 5 * 60 * 1000, // 5분

    // 인증 관련
    USER_PERMISSIONS: 5 * 60 * 1000, // 5분
    USER_ROLES: 5 * 60 * 1000, // 5분

    // 일반 데이터
    GENERAL_DATA: 5 * 60 * 1000, // 5분
    STATIC_DATA: 60 * 60 * 1000, // 1시간

    // 세션 관련
    SESSION_DATA: 30 * 60 * 1000, // 30분
  },

  // 캐시 키 접두사
  KEY_PREFIXES: {
    DASHBOARD: {
      STATS: 'dashboard:stats',
      ACTIVITIES: 'dashboard:activities',
      ADVANCED_STATS: 'dashboard:advanced_stats',
    },
    PROFILE: {
      USER: 'profile:user',
    },
    OAUTH2: {
      SCOPES: 'oauth2:scopes',
      CLIENTS: 'oauth2:clients',
    },
    AUTH: {
      PERMISSIONS: 'auth:permissions',
      ROLES: 'auth:roles',
    },
    SESSION: {
      DATA: 'session:data',
    },
  },
} as const;

/**
 * 캐시 키 생성 헬퍼 함수들
 */
export const CACHE_KEYS = {
  // 대시보드
  dashboard: {
    stats: (userId: number) =>
      `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.STATS}:${userId}`,
    activities: (userId: number) =>
      `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ACTIVITIES}:${userId}`,
    advancedStats: (userId: number, days: number) =>
      `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ADVANCED_STATS}:${userId}:${days}`,
  },

  // 프로필
  profile: {
    user: (userId: number) =>
      `${CACHE_CONFIG.KEY_PREFIXES.PROFILE.USER}:${userId}`,
  },

  // OAuth2
  oauth2: {
    scopes: {
      all: () => `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.SCOPES}:all`,
      byId: (id: number) =>
        `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.SCOPES}:id:${id}`,
    },
    clients: {
      byId: (id: number) =>
        `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.CLIENTS}:id:${id}`,
      byUser: (userId: number) =>
        `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.CLIENTS}:user:${userId}`,
    },
    token: (accessToken: string) =>
      `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.CLIENTS}:token:${accessToken}`,
  },

  // 인증
  auth: {
    permissions: (userId: number) =>
      `${CACHE_CONFIG.KEY_PREFIXES.AUTH.PERMISSIONS}:${userId}`,
    roles: (userId: number) =>
      `${CACHE_CONFIG.KEY_PREFIXES.AUTH.ROLES}:${userId}`,
  },

  // 세션
  session: {
    data: (sessionId: string) =>
      `${CACHE_CONFIG.KEY_PREFIXES.SESSION.DATA}:${sessionId}`,
  },
} as const;

/**
 * 캐시 무효화 패턴들 (Redis SCAN용)
 */
export const CACHE_INVALIDATION_PATTERNS = {
  // 사용자별 캐시 무효화
  user: (userId: number) => [
    `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.STATS}:${userId}`,
    `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ACTIVITIES}:${userId}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ADVANCED_STATS}:${userId}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.PROFILE.USER}:${userId}`,
    `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.CLIENTS}:user:${userId}`,
    `${CACHE_CONFIG.KEY_PREFIXES.AUTH.PERMISSIONS}:${userId}`,
    `${CACHE_CONFIG.KEY_PREFIXES.AUTH.ROLES}:${userId}`,
  ],

  // 모든 사용자 캐시 무효화
  allUsers: () => [
    `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.STATS}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ACTIVITIES}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ADVANCED_STATS}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.PROFILE.USER}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.CLIENTS}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.AUTH.PERMISSIONS}:*`,
    `${CACHE_CONFIG.KEY_PREFIXES.AUTH.ROLES}:*`,
  ],

  // 특정 타입의 캐시 무효화
  byType: {
    dashboard: [
      `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.STATS}:*`,
      `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ACTIVITIES}:*`,
      `${CACHE_CONFIG.KEY_PREFIXES.DASHBOARD.ADVANCED_STATS}:*`,
    ],
    oauth2: [
      `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.SCOPES}:*`,
      `${CACHE_CONFIG.KEY_PREFIXES.OAUTH2.CLIENTS}:*`,
    ],
    auth: [
      `${CACHE_CONFIG.KEY_PREFIXES.AUTH.PERMISSIONS}:*`,
      `${CACHE_CONFIG.KEY_PREFIXES.AUTH.ROLES}:*`,
    ],
  },
} as const;
