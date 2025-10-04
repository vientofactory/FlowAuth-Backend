import { ApiProperty } from '@nestjs/swagger';

/**
 * OAuth2 사용자 정보 응답 DTO
 */
export class UserinfoResponseDto {
  @ApiProperty({
    description: '사용자 식별자',
    example: '12345',
  })
  sub: string;

  @ApiProperty({
    description: '이름 (profile 스코프 필요)',
    example: 'John Doe',
    required: false,
  })
  name?: string;

  @ApiProperty({
    description: '이름 (profile 스코프 필요)',
    example: 'John',
    required: false,
  })
  given_name?: string;

  @ApiProperty({
    description: '성 (profile 스코프 필요)',
    example: 'Doe',
    required: false,
  })
  family_name?: string;

  @ApiProperty({
    description: '사용자명 (profile 스코프 필요)',
    example: 'john_doe',
    required: false,
  })
  preferred_username?: string;

  @ApiProperty({
    description: '프로필 URL (profile 스코프 필요)',
    example: 'https://example.com/users/12345',
    required: false,
  })
  profile?: string;

  @ApiProperty({
    description: '프로필 이미지 URL (profile 스코프 필요)',
    example: 'https://example.com/avatars/12345.jpg',
    required: false,
  })
  picture?: string;

  @ApiProperty({
    description: '이메일 주소 (email 스코프 필요)',
    example: 'user@example.com',
    required: false,
  })
  email?: string;

  @ApiProperty({
    description: '이메일 검증 여부 (email 스코프 필요)',
    example: true,
    required: false,
  })
  email_verified?: boolean;

  @ApiProperty({
    description: '성별 (profile 스코프 필요)',
    example: 'male',
    enum: ['male', 'female', 'other'],
    required: false,
  })
  gender?: string;

  @ApiProperty({
    description: '생년월일 (profile 스코프 필요)',
    example: '1990-01-01',
    required: false,
  })
  birthdate?: string;

  @ApiProperty({
    description: '시간대 (profile 스코프 필요)',
    example: 'Asia/Seoul',
    required: false,
  })
  zoneinfo?: string;

  @ApiProperty({
    description: '로케일 (profile 스코프 필요)',
    example: 'ko-KR',
    required: false,
  })
  locale?: string;

  @ApiProperty({
    description: '마지막 업데이트 시간 (profile 스코프 필요)',
    example: 1638360000,
    required: false,
  })
  updated_at?: number;

  @ApiProperty({
    description: '사용자 역할 (profile 스코프 필요)',
    example: ['user'],
    type: [String],
    required: false,
  })
  roles?: string[];
}

/**
 * OAuth2 클라이언트 정보 DTO
 */
export class ClientInfoDto {
  @ApiProperty({
    description: '클라이언트 ID',
    example: 'my-client-app',
  })
  id: string;

  @ApiProperty({
    description: '클라이언트 이름',
    example: 'My Application',
  })
  name: string;

  @ApiProperty({
    description: '클라이언트 설명',
    example: 'A sample OAuth2 client application',
    required: false,
  })
  description?: string;

  @ApiProperty({
    description: '클라이언트 로고 URI',
    example: 'https://example.com/logo.png',
    required: false,
  })
  logoUri?: string;

  @ApiProperty({
    description: '이용약관 URI',
    example: 'https://example.com/terms',
    required: false,
  })
  termsOfServiceUri?: string;

  @ApiProperty({
    description: '개인정보 정책 URI',
    example: 'https://example.com/privacy',
    required: false,
  })
  policyUri?: string;
}

/**
 * OAuth2 인증 정보 응답 DTO
 */
export class AuthorizeInfoResponseDto {
  @ApiProperty({
    description: '클라이언트 정보',
    type: ClientInfoDto,
  })
  client: ClientInfoDto;

  @ApiProperty({
    description: '요청된 스코프 목록',
    example: ['openid', 'profile', 'email'],
    type: [String],
  })
  scopes: string[];
}

/**
 * OAuth2 대시보드 통계 응답 DTO
 */
export class DashboardStatsResponseDto {
  @ApiProperty({
    description: '등록된 클라이언트 총 개수',
    example: 5,
  })
  totalClients: number;

  @ApiProperty({
    description: '활성 토큰 개수',
    example: 12,
  })
  activeTokens: number;

  @ApiProperty({
    description: '마지막 로그인 날짜',
    example: '2023-12-01T10:30:00Z',
    type: Date,
    required: false,
  })
  lastLoginDate: Date | null;

  @ApiProperty({
    description: '계정 생성 날짜',
    example: '2023-01-15T09:00:00Z',
    type: Date,
    required: false,
  })
  accountCreated: Date | null;
}
