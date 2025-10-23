/**
 * 레이트 리미팅 및 입력 크기 제한 설정
 */
import * as crypto from 'crypto';
import type { Request } from 'express';

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    sub?: string;
    client_id?: string;
    scopes?: string[];
    token_type?: string;
    [key: string]: unknown;
  };
}

// Validation Pipe 관련 설정
export const VALIDATION_PIPE_OPTIONS = {
  maxPayloadSize: 1024 * 1024, // 1MB
  skipPayloadSizeValidationForFileUploads: true,
  whitelist: true,
  forbidNonWhitelisted: true,
  forbidUnknownValues: true,
} as const;

// 파일 업로드 관련 DTO 클래스 이름 패턴 (페이로드 크기 검증 제외용)
export const FILE_UPLOAD_DTO_PATTERNS = [
  /Upload.*Dto$/,
  /.*Upload.*$/,
  /File.*Dto$/,
  /.*File.*$/,
] as const;

// 엔드포인트별 레이트 리미팅 설정
export const RATE_LIMIT_CONFIGS = {
  // 인증 관련 엔드포인트 (더 엄격)
  AUTH_LOGIN: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 5, // 15분에 5회
    message: '로그인 시도가 너무 많습니다. 15분 후 다시 시도해주세요.',
  },
  AUTH_REGISTER: {
    windowMs: 60 * 60 * 1000, // 1시간
    maxRequests: 3, // 1시간에 3회
    message: '회원가입 시도가 너무 많습니다. 1시간 후 다시 시도해주세요.',
  },
  AUTH_PASSWORD_RESET: {
    windowMs: 60 * 60 * 1000, // 1시간
    maxRequests: 3, // 1시간에 3회
    message:
      '비밀번호 재설정 요청이 너무 많습니다. 1시간 후 다시 시도해주세요.',
  },
  AUTH_2FA_VERIFY: {
    windowMs: 5 * 60 * 1000, // 5분
    maxRequests: 10, // 5분에 10회
    message: '2FA 인증 시도가 너무 많습니다. 5분 후 다시 시도해주세요.',
  },
  AUTH_BACKUP_CODE: {
    windowMs: 5 * 60 * 1000, // 5분
    maxRequests: 5, // 5분에 5회 (백업코드는 더 제한적)
    message: '백업 코드 인증 시도가 너무 많습니다. 5분 후 다시 시도해주세요.',
  },

  // OAuth2 관련 엔드포인트
  OAUTH2_TOKEN: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 20, // 15분에 20회
    message: '토큰 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
  },
  OAUTH2_AUTHORIZE: {
    windowMs: 5 * 60 * 1000, // 5분
    maxRequests: 30, // 5분에 30회
    message: '인증 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
  },

  // API 엔드포인트 (일반적)
  API_GENERAL: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 100, // 15분에 100회
    message: 'API 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
  },
  API_UPLOAD: {
    windowMs: 60 * 60 * 1000, // 1시간
    maxRequests: 10, // 1시간에 10회
    message: '파일 업로드 요청이 너무 많습니다. 1시간 후 다시 시도해주세요.',
  },

  // 관리자 엔드포인트 (더 관대)
  ADMIN_GENERAL: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 200, // 15분에 200회
    message: '관리자 API 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
  },
} as const;

// 입력 크기 제한 설정
export const SIZE_LIMIT_CONFIGS = {
  // 일반 API 요청
  DEFAULT: {
    maxBodySize: 1024 * 1024, // 1MB
    maxUrlLength: 2048, // 2KB
    maxHeaderSize: 8192, // 8KB
    maxFieldLength: 1000, // 1KB
  },

  // 파일 업로드 (더 큰 크기 허용)
  FILE_UPLOAD: {
    maxBodySize: 10 * 1024 * 1024, // 10MB
    maxUrlLength: 2048,
    maxHeaderSize: 16384, // 16KB (더 큰 헤더 허용)
    maxFieldLength: 2000, // 2KB
  },

  // 프로필 이미지 업로드
  PROFILE_IMAGE: {
    maxBodySize: 5 * 1024 * 1024, // 5MB
    maxUrlLength: 2048,
    maxHeaderSize: 8192,
    maxFieldLength: 1000,
  },

  // OAuth2 요청 (더 작은 크기)
  OAUTH2: {
    maxBodySize: 16 * 1024, // 16KB
    maxUrlLength: 4096, // 4KB (긴 redirect_uri 등을 위해)
    maxHeaderSize: 8192,
    maxFieldLength: 2048, // OAuth2 토큰 등을 위해
  },

  // 인증 요청 (reCAPTCHA 토큰을 고려한 크기)
  AUTH: {
    maxBodySize: 8 * 1024, // 8KB (reCAPTCHA 토큰 포함)
    maxUrlLength: 2048,
    maxHeaderSize: 8192,
    maxFieldLength: 2500, // reCAPTCHA 토큰은 최대 2000자 정도
  },

  // reCAPTCHA 전용 설정 (더 큰 토큰 허용)
  RECAPTCHA: {
    maxBodySize: 8 * 1024, // 8KB
    maxUrlLength: 2048,
    maxHeaderSize: 8192,
    maxFieldLength: 3000, // reCAPTCHA 토큰 최대 길이
  },
} as const;

// IP별 특별 제한 설정
export const IP_BASED_LIMITS = {
  // 의심스러운 활동을 보이는 IP
  SUSPICIOUS_IP: {
    windowMs: 60 * 60 * 1000, // 1시간
    maxRequests: 10, // 1시간에 10회만 허용
    message: '보안상의 이유로 일시적으로 제한됩니다.',
  },

  // 개발/테스트 환경 IP (더 관대)
  DEVELOPMENT_IP: {
    windowMs: 60 * 1000, // 1분
    maxRequests: 1000, // 1분에 1000회
    message: '개발 환경 제한 초과',
  },
} as const;

// 사용자 역할별 제한 설정
export const ROLE_BASED_LIMITS = {
  GUEST: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 20, // 15분에 20회
  },
  USER: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 100, // 15분에 100회
  },
  PREMIUM_USER: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 200, // 15분에 200회
  },
  ADMIN: {
    windowMs: 15 * 60 * 1000, // 15분
    maxRequests: 500, // 15분에 500회
  },
} as const;

// 동적 키 생성기들
export const KEY_GENERATORS = {
  // IP + 엔드포인트 기반
  IP_ENDPOINT: (req: AuthenticatedRequest) => {
    const ip = getClientIp(req);
    return `rate_limit:ip:${ip}:${req.path || 'unknown'}`;
  },

  // 사용자 ID 기반 (인증된 사용자)
  USER_ID: (req: AuthenticatedRequest) => {
    const userId = req.user?.id || 'anonymous';
    return `rate_limit:user:${userId}:${req.path || 'unknown'}`;
  },

  // Client ID 기반 (OAuth2)
  CLIENT_ID: (req: AuthenticatedRequest) => {
    let clientId = 'unknown';
    try {
      const body = req.body as { client_id?: string };
      const query = req.query as { client_id?: string };
      clientId = body?.client_id || query?.client_id || 'unknown';
    } catch {
      clientId = 'unknown';
    }
    return `rate_limit:client:${clientId}:${req.path || 'unknown'}`;
  },

  // IP + User Agent 기반 (봇 탐지)
  IP_USER_AGENT: (req: AuthenticatedRequest) => {
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'unknown';
    const hash = crypto
      .createHash('md5')
      .update(userAgent)
      .digest('hex')
      .substring(0, 8);
    return `rate_limit:ip_ua:${ip}:${hash}:${req.path || 'unknown'}`;
  },
} as const;

// IP 주소 추출 유틸리티 함수
function getClientIp(req: AuthenticatedRequest): string {
  const cfConnectingIp = req.headers['cf-connecting-ip'];
  const xForwardedFor = req.headers['x-forwarded-for'];

  if (typeof cfConnectingIp === 'string') {
    return cfConnectingIp;
  }

  if (typeof xForwardedFor === 'string') {
    return xForwardedFor.split(',')[0]?.trim() || 'unknown';
  }

  if (Array.isArray(xForwardedFor) && xForwardedFor.length > 0) {
    return xForwardedFor[0].split(',')[0]?.trim() || 'unknown';
  }

  // Fallback to other IP sources
  try {
    const connection = req.connection as { remoteAddress?: string };
    if (connection?.remoteAddress) {
      return connection.remoteAddress;
    }

    const socket = req.socket as { remoteAddress?: string };
    if (socket?.remoteAddress) {
      return socket.remoteAddress;
    }

    if (req.ip) {
      return req.ip;
    }
  } catch {
    // Ignore errors and return unknown
  }

  return 'unknown';
}
