import { ApiProperty } from '@nestjs/swagger';

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
    description: '총 토큰 발급 수',
    example: 156,
  })
  totalTokensIssued: number;

  @ApiProperty({
    description: '만료된 토큰 수',
    example: 23,
  })
  expiredTokens: number;

  @ApiProperty({
    description: '취소된 토큰 수',
    example: 8,
  })
  revokedTokens: number;

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

  @ApiProperty({
    description: '시간별 토큰 발급 통계 (최근 24시간)',
    example: [
      { hour: '00:00', count: 5 },
      { hour: '01:00', count: 3 },
    ],
  })
  tokenIssuanceByHour: Array<{ hour: string; count: number }>;

  @ApiProperty({
    description: '일별 토큰 발급 통계 (최근 30일)',
    example: [
      { date: '2024-01-01', count: 25 },
      { date: '2024-01-02', count: 18 },
    ],
  })
  tokenIssuanceByDay: Array<{ date: string; count: number }>;

  @ApiProperty({
    description: '클라이언트별 토큰 사용량',
    example: [
      { clientName: 'MyApp', tokenCount: 45, percentage: 28.7 },
      { clientName: 'TestApp', tokenCount: 32, percentage: 20.4 },
    ],
  })
  clientUsageStats: Array<{
    clientName: string;
    tokenCount: number;
    percentage: number;
  }>;

  @ApiProperty({
    description: '스코프별 사용 통계',
    example: [
      { scope: 'read', count: 89, percentage: 56.7 },
      { scope: 'write', count: 45, percentage: 28.7 },
    ],
  })
  scopeUsageStats: Array<{
    scope: string;
    count: number;
    percentage: number;
  }>;

  @ApiProperty({
    description: '토큰 만료율 (%)',
    example: 15.2,
  })
  tokenExpirationRate: number;

  @ApiProperty({
    description: '평균 토큰 수명 (시간)',
    example: 168,
  })
  averageTokenLifetime: number;

  @ApiProperty({
    description: '인사이트 및 분석',
    example: {
      trends: '토큰 발급량이 최근 7일간 23% 증가했습니다.',
      recommendations:
        '보안 강화를 위해 토큰 만료 시간을 단축하는 것을 고려해보세요.',
      alerts: '만료율이 15%를 초과했습니다.',
    },
  })
  insights: {
    trends: string;
    recommendations: string;
    alerts: string;
  };
}
