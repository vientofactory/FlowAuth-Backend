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
