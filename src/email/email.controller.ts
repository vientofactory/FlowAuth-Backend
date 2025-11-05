import {
  Controller,
  Post,
  Body,
  Get,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { EmailService } from './email.service';

@Controller('email')
@ApiTags('Email Testing')
export class EmailController {
  constructor(private readonly emailService: EmailService) {}

  @Get('test-connection')
  @ApiOperation({ summary: 'SMTP 연결 테스트' })
  @ApiResponse({
    status: 200,
    description: 'SMTP 연결 테스트 결과',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        message: { type: 'string' },
      },
    },
  })
  async testConnection(): Promise<{ success: boolean; message: string }> {
    const isConnected = await this.emailService.testConnection();
    return {
      success: isConnected,
      message: isConnected ? 'SMTP 연결 성공' : 'SMTP 연결 실패',
    };
  }

  @Post('test-send')
  @ApiOperation({
    summary: '테스트 이메일 전송',
    description: '개발 환경에서만 사용하는 테스트용 이메일 전송 엔드포인트',
  })
  @ApiResponse({
    status: 200,
    description: '테스트 이메일 전송 완료',
  })
  @ApiResponse({
    status: 400,
    description: '이메일 전송 실패',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        to: { type: 'string', format: 'email', example: 'test@example.com' },
        templateName: {
          type: 'string',
          example: 'welcome',
          enum: [
            'welcome',
            'email-verification',
            'password-reset',
            '2fa-enabled',
            'client-created',
            'security-alert',
          ],
        },
        username: { type: 'string', example: 'testuser' },
      },
      required: ['to', 'templateName', 'username'],
    },
  })
  sendTestEmail(
    @Body() body: { to: string; templateName: string; username: string },
  ): { message: string } {
    const { to, templateName, username } = body;

    try {
      switch (templateName) {
        case 'welcome':
          this.emailService.sendWelcomeEmailAsync(to, username);
          break;
        case 'email-verification':
          this.emailService.sendEmailVerificationAsync(
            to,
            username,
            'test-token-123456',
          );
          break;
        case 'password-reset':
          this.emailService.sendPasswordResetAsync(
            to,
            username,
            'test-reset-token-123456',
          );
          break;
        case '2fa-enabled':
          this.emailService.send2FAEnabledAsync(to, username);
          break;
        case 'client-created':
          this.emailService.sendClientCreatedAsync(
            to,
            username,
            'Test Client',
            'test-client-id',
          );
          break;
        case 'security-alert':
          this.emailService.sendSecurityAlertAsync(
            to,
            username,
            '테스트 알림',
            {
              action: '테스트 보안 활동',
              ipAddress: '127.0.0.1',
              userAgent: 'Test Browser',
            },
          );
          break;
        default:
          throw new Error('지원되지 않는 템플릿입니다.');
      }

      return {
        message: `${templateName} 템플릿 이메일이 ${to}로 큐에 추가되었습니다 (백그라운드에서 전송됩니다).`,
      };
    } catch (error) {
      throw new BadRequestException(
        `이메일 큐 추가 실패: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }
}
