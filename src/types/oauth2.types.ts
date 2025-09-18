// OAuth2 전용 타입 정의들
export interface OAuth2JwtPayload {
  sub: number | null; // 사용자 ID (client credentials grant에서는 null)
  client_id: string; // 클라이언트 ID
  scopes: string[]; // 허용된 스코프 목록
  token_type: 'Bearer'; // 토큰 타입 (항상 Bearer)
  iat?: number; // 발급 시간
  exp?: number; // 만료 시간
}

export interface OAuth2AuthenticatedRequest extends Request {
  user: OAuth2JwtPayload;
}

// OAuth2 스코프 관련 타입들
export interface ScopeDefinition {
  name: string;
  description: string;
  resource?: string; // 스코프가 적용되는 리소스
  action?: string; // 스코프가 허용하는 액션
}

// OAuth2 리소스 서버 응답 타입들
export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  sub?: string;
  exp?: number;
  iat?: number;
  token_type?: string;
}

export interface OAuth2ErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

// OAuth2 스코프 검증 결과
export interface ScopeValidationResult {
  isValid: boolean;
  missingScopes?: string[];
  invalidScopes?: string[];
}

// OAuth2 토큰 메타데이터
export interface TokenMetadata {
  clientId: string;
  userId?: number;
  scopes: string[];
  issuedAt: Date;
  expiresAt: Date;
  tokenType: 'Bearer';
}
