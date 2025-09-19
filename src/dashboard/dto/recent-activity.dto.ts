import { ApiProperty } from '@nestjs/swagger';

export class RecentActivityDto {
  @ApiProperty({
    description: '활동 ID',
    example: 1,
  })
  id: number;

  @ApiProperty({
    description: '활동 타입',
    example: 'login',
    enum: [
      'login',
      'account_created',
      'client_created',
      'token_created',
      'client_updated',
      'token_revoked',
    ],
  })
  type:
    | 'login'
    | 'account_created'
    | 'client_created'
    | 'token_created'
    | 'client_updated'
    | 'token_revoked';

  @ApiProperty({
    description: '활동 설명',
    example: '로그인',
  })
  description: string;

  @ApiProperty({
    description: '활동 발생 시간',
    example: '2025-09-19T10:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: '관련 리소스 ID (선택사항)',
    example: 123,
    required: false,
  })
  resourceId?: number;

  @ApiProperty({
    description: '추가 메타데이터',
    example: { clientName: 'My App' },
    required: false,
  })
  metadata?: Record<string, any>;
}
