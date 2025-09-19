import { IsBoolean, IsNumber, Min, Max } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SecuritySettingsDto {
  @ApiProperty({
    description: '2단계 인증 활성화',
    example: false,
  })
  @IsBoolean()
  enableTwoFactor: boolean;

  @ApiProperty({
    description: '강력한 비밀번호 요구',
    example: true,
  })
  @IsBoolean()
  requireStrongPasswords: boolean;

  @ApiProperty({
    description: '로그인 알림 활성화',
    example: true,
  })
  @IsBoolean()
  enableLoginNotifications: boolean;

  @ApiProperty({
    description: '세션 타임아웃 (초)',
    example: 1800,
    minimum: 300,
    maximum: 86400,
  })
  @IsNumber()
  @Min(300)
  @Max(86400)
  sessionTimeout: number;

  @ApiProperty({
    description: '최대 로그인 시도 횟수',
    example: 5,
    minimum: 3,
    maximum: 20,
  })
  @IsNumber()
  @Min(3)
  @Max(20)
  maxLoginAttempts: number;

  @ApiProperty({
    description: '감사 로그 활성화',
    example: true,
  })
  @IsBoolean()
  enableAuditLog: boolean;
}
