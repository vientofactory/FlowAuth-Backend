import { IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class NotificationSettingsDto {
  @ApiProperty({
    description: '이메일 알림 활성화',
    example: true,
  })
  @IsBoolean()
  emailNotifications: boolean;

  @ApiProperty({
    description: '새 클라이언트 등록 알림',
    example: true,
  })
  @IsBoolean()
  newClientNotifications: boolean;

  @ApiProperty({
    description: '토큰 만료 알림',
    example: true,
  })
  @IsBoolean()
  tokenExpiryNotifications: boolean;

  @ApiProperty({
    description: '보안 경고 알림',
    example: true,
  })
  @IsBoolean()
  securityAlerts: boolean;

  @ApiProperty({
    description: '시스템 업데이트 알림',
    example: false,
  })
  @IsBoolean()
  systemUpdates: boolean;
}
