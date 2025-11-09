import {
  Controller,
  Post,
  Body,
  Get,
  BadRequestException,
  UseGuards,
  Delete,
  Param,
  Query,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { EmailService } from './email.service';
import { EmailQueueService } from './email-queue.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import {
  PermissionsGuard,
  RequireAdminPermission,
} from 'src/auth/permissions.guard';

@Controller('email')
@ApiBearerAuth()
@ApiTags('Email Management')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@RequireAdminPermission()
export class EmailController {
  constructor(
    private readonly emailService: EmailService,
    private readonly emailQueueService: EmailQueueService,
  ) {}

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

  @Get('smtp-info')
  @ApiOperation({ summary: 'SMTP 연결 정보 조회' })
  @ApiResponse({
    status: 200,
    description: 'SMTP 연결 정보 및 상태',
    schema: {
      type: 'object',
      properties: {
        connected: { type: 'boolean' },
        host: { type: 'string' },
        port: { type: 'number' },
        auth: { type: 'string' },
        secure: { type: 'boolean' },
        lastChecked: { type: 'string' },
      },
    },
  })
  async getSmtpInfo(): Promise<{
    connected: boolean;
    host: string;
    port: number;
    auth: string;
    secure: boolean;
    lastChecked: string;
  }> {
    return await this.emailService.getSmtpInfo();
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
  async sendTestEmail(
    @Body() body: { to: string; templateName: string; username: string },
  ): Promise<{ message: string }> {
    const { to, templateName, username } = body;

    try {
      switch (templateName) {
        case 'welcome':
          await this.emailService.queueWelcomeEmail(to, username);
          break;
        case 'email-verification':
          await this.emailService.queueEmailVerification(
            to,
            username,
            'test-token-123456',
          );
          break;
        case 'password-reset':
          await this.emailService.queuePasswordReset(
            to,
            username,
            'test-reset-token-123456',
          );
          break;
        case '2fa-enabled':
          await this.emailService.queue2FAEnabled(to, username);
          break;
        case 'client-created':
          await this.emailService.queueClientCreated(
            to,
            username,
            'Test Client',
            'test-client-id',
          );
          break;
        case 'security-alert':
          await this.emailService.queueSecurityAlert(
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

  @Get('queue/stats')
  @ApiOperation({ summary: '이메일 큐 상태 조회' })
  @ApiResponse({
    status: 200,
    description: '이메일 큐 통계 정보',
    schema: {
      type: 'object',
      properties: {
        active: { type: 'number', description: '처리 중인 작업 수' },
        waiting: { type: 'number', description: '대기 중인 작업 수' },
        completed: { type: 'number', description: '완료된 작업 수' },
        failed: { type: 'number', description: '실패한 작업 수' },
        delayed: { type: 'number', description: '지연된 작업 수' },
        paused: { type: 'number', description: '일시정지 상태' },
      },
    },
  })
  async getQueueStats() {
    return await this.emailQueueService.getQueueStats();
  }

  @Post('queue/retry-failed')
  @ApiOperation({ summary: '실패한 이메일 작업 재시도' })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: 'number',
    description: '재시도할 작업 수 제한 (기본: 10)',
  })
  @ApiResponse({
    status: 200,
    description: '재시도한 작업 수',
    schema: {
      type: 'object',
      properties: {
        retriedCount: { type: 'number', description: '재시도한 작업 수' },
      },
    },
  })
  async retryFailedJobs(@Query('limit') limit?: number) {
    const retriedCount = await this.emailQueueService.retryFailedJobs(
      limit ?? 10,
    );
    return { retriedCount };
  }

  @Post('queue/clean')
  @ApiOperation({ summary: '이메일 큐 정리' })
  @ApiQuery({
    name: 'grace',
    required: false,
    type: 'number',
    description: '보존할 시간 (밀리초, 기본: 24시간)',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: 'number',
    description: '정리할 작업 수 제한 (기본: 1000)',
  })
  @ApiResponse({
    status: 200,
    description: '큐 정리 완료',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  async cleanQueue(
    @Query('grace') grace?: number,
    @Query('limit') limit?: number,
  ) {
    const result = await this.emailQueueService.cleanQueue(
      grace ?? 86400000, // 24시간 보존 (디버깅을 위한 작업 기록 유지)
      limit ?? 1000,
    );
    return {
      message: '큐 정리가 완료되었습니다.',
      cleanedCompleted: result.cleanedCompleted,
      cleanedFailed: result.cleanedFailed,
      totalCleaned: result.cleanedCompleted + result.cleanedFailed,
    };
  }

  @Post('queue/pause')
  @ApiOperation({ summary: '이메일 큐 일시정지' })
  @ApiResponse({
    status: 200,
    description: '큐 일시정지 완료',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  async pauseQueue() {
    await this.emailQueueService.pauseQueue();
    return { message: '이메일 큐가 일시정지되었습니다.' };
  }

  @Post('queue/resume')
  @ApiOperation({ summary: '이메일 큐 재개' })
  @ApiResponse({
    status: 200,
    description: '큐 재개 완료',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  async resumeQueue() {
    await this.emailQueueService.resumeQueue();
    return { message: '이메일 큐가 재개되었습니다.' };
  }

  @Delete('queue/job/:jobId')
  @ApiOperation({ summary: '특정 이메일 작업 제거' })
  @ApiParam({ name: 'jobId', type: 'string', description: '작업 ID' })
  @ApiResponse({
    status: 200,
    description: '작업 제거 결과',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        message: { type: 'string' },
      },
    },
  })
  async removeJob(@Param('jobId') jobId: string) {
    const success = await this.emailQueueService.removeJob(jobId);
    return {
      success,
      message: success
        ? `작업 ${jobId}이(가) 제거되었습니다.`
        : `작업 ${jobId}을(를) 찾을 수 없습니다.`,
    };
  }

  @Delete('queue/purge')
  @ApiOperation({
    summary: '이메일 큐 완전 비우기',
    description: '주의: 모든 작업이 삭제됩니다.',
  })
  @ApiResponse({
    status: 200,
    description: '큐 비우기 완료',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  async purgeQueue() {
    await this.emailQueueService.purgeQueue();
    return { message: '이메일 큐의 모든 작업이 제거되었습니다.' };
  }
}
