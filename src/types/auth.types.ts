import { User } from '../auth/user.entity';
import { TokenType } from '@flowauth/shared';

// 인증 관련 타입 정의들
export interface JwtPayload {
  sub: string;
  email: string;
  username: string;
  roles: string[];
  permissions: number;
  type: TokenType;
  avatar?: string;
  jti?: string; // JWT ID for token revocation
  iat?: number;
  exp?: number;
}

export interface LoginResponse {
  user: User;
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
}

export interface AuthenticatedRequest {
  user: User;
}

// Express Request 확장을 위한 타입
export interface RequestWithUser extends Request {
  user: User;
}

// Express Request 헤더 타입
export interface RequestHeaders {
  authorization?: string;
  [key: string]: string | string[] | undefined;
}

// Express Request의 기본 구조
export interface ExpressRequest {
  headers: RequestHeaders;
  [key: string]: unknown;
}
