import { ApiProperty } from '@nestjs/swagger';

export class ConnectedAppDto {
  @ApiProperty({
    description: '클라이언트 ID',
    example: 1,
  })
  id: number;

  @ApiProperty({
    description: '클라이언트 이름',
    example: 'My Awesome App',
  })
  name: string;

  @ApiProperty({
    description: '클라이언트 설명',
    example: '사용자의 데이터를 관리하는 애플리케이션',
    required: false,
  })
  description?: string;

  @ApiProperty({
    description: '클라이언트 로고 URL',
    example: 'https://example.com/logo.png',
    required: false,
  })
  logoUrl?: string;

  @ApiProperty({
    description: '연결된 권한 범위 목록',
    example: ['identify', 'email'],
    type: [String],
  })
  scopes: string[];

  @ApiProperty({
    description: '토큰 발급 일시',
    example: '2024-01-15T10:30:00Z',
  })
  connectedAt: Date;

  @ApiProperty({
    description: '마지막 토큰 사용 일시',
    example: '2024-01-20T14:45:00Z',
    required: false,
  })
  lastUsedAt?: Date;

  @ApiProperty({
    description: '토큰 만료 일시',
    example: '2024-01-22T10:30:00Z',
  })
  expiresAt: Date;

  @ApiProperty({
    description: '토큰 상태',
    example: 'active',
    enum: ['active', 'expired', 'revoked'],
  })
  status: 'active' | 'expired' | 'revoked';
}

export class ConnectedAppsResponseDto {
  @ApiProperty({
    description: '연결된 앱 목록',
    type: [ConnectedAppDto],
  })
  apps: ConnectedAppDto[];

  @ApiProperty({
    description: '총 연결된 앱 수',
    example: 5,
  })
  total: number;
}

export class RevokeConnectionDto {
  @ApiProperty({
    description: '연결을 해제할 클라이언트 ID',
    example: 1,
  })
  clientId: number;
}

export class RevokeConnectionResponseDto {
  @ApiProperty({
    description: '연결 해제 성공 여부',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: '해제된 토큰 수',
    example: 2,
  })
  revokedTokensCount: number;

  @ApiProperty({
    description: '응답 메시지',
    example: '연결이 성공적으로 해제되었습니다.',
  })
  message: string;
}
