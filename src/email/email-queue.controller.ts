import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { EmailQueueService } from './email-queue.service';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import {
  PermissionsGuard,
  RequireAdminPermission,
} from '../auth/permissions.guard';

@ApiTags('Email Queue Management')
@ApiBearerAuth()
@Controller('admin/email-queue')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@RequireAdminPermission()
export class EmailQueueController {
  constructor(
    private readonly emailQueueService: EmailQueueService,
    @InjectQueue('email')
    private readonly emailQueue: Queue,
  ) {}

  /**
   * 큐 상태 조회
   */
  @Get('stats')
  @ApiOperation({ summary: '이메일 큐 통계 조회' })
  @ApiResponse({ status: 200, description: '큐 통계 정보' })
  @ApiResponse({ status: 401, description: '인증이 필요합니다' })
  @ApiResponse({ status: 403, description: '관리자 권한이 필요합니다' })
  async getQueueStats() {
    return await this.emailQueueService.getQueueStats();
  }

  /**
   * 대기 중인 작업 목록 조회
   */
  @Get('jobs/waiting')
  @ApiOperation({ summary: '대기 중인 작업 목록 조회' })
  @ApiResponse({ status: 200, description: '대기 중인 작업 목록' })
  async getWaitingJobs(@Query('start') start = 0, @Query('end') end = 10) {
    const jobs = await this.emailQueue.getWaiting(start, end);
    return jobs.map((job) => ({
      id: job.id,
      data: job.data as unknown,
      opts: job.opts,
      timestamp: job.timestamp,
      processedOn: job.processedOn,
      finishedOn: job.finishedOn,
      progress: job.progress() as unknown,
    }));
  }

  /**
   * 활성 작업 목록 조회
   */
  @Get('jobs/active')
  @ApiOperation({ summary: '활성 작업 목록 조회' })
  @ApiResponse({ status: 200, description: '활성 작업 목록' })
  async getActiveJobs() {
    const jobs = await this.emailQueue.getActive();
    return jobs.map((job) => ({
      id: job.id,
      data: job.data as unknown,
      opts: job.opts,
      timestamp: job.timestamp,
      processedOn: job.processedOn,
      progress: job.progress() as unknown,
    }));
  }

  /**
   * 완료된 작업 목록 조회
   */
  @Get('jobs/completed')
  @ApiOperation({ summary: '완료된 작업 목록 조회' })
  @ApiResponse({ status: 200, description: '완료된 작업 목록' })
  async getCompletedJobs(@Query('start') start = 0, @Query('end') end = 10) {
    const jobs = await this.emailQueue.getCompleted(start, end);
    return jobs.map((job) => ({
      id: job.id,
      data: job.data as unknown,
      opts: job.opts,
      timestamp: job.timestamp,
      processedOn: job.processedOn,
      finishedOn: job.finishedOn,
      returnvalue: job.returnvalue as unknown,
    }));
  }

  /**
   * 실패한 작업 목록 조회
   */
  @Get('jobs/failed')
  @ApiOperation({ summary: '실패한 작업 목록 조회' })
  @ApiResponse({ status: 200, description: '실패한 작업 목록' })
  async getFailedJobs(@Query('start') start = 0, @Query('end') end = 10) {
    const jobs = await this.emailQueue.getFailed(start, end);
    return jobs.map((job) => ({
      id: job.id,
      data: job.data as unknown,
      opts: job.opts,
      timestamp: job.timestamp,
      processedOn: job.processedOn,
      finishedOn: job.finishedOn,
      failedReason: job.failedReason,
      stacktrace: job.stacktrace,
      attemptsMade: job.attemptsMade,
    }));
  }

  /**
   * 지연된 작업 목록 조회
   */
  @Get('jobs/delayed')
  @ApiOperation({ summary: '지연된 작업 목록 조회' })
  @ApiResponse({ status: 200, description: '지연된 작업 목록' })
  async getDelayedJobs(@Query('start') start = 0, @Query('end') end = 10) {
    const jobs = await this.emailQueue.getDelayed(start, end);
    return jobs.map((job) => ({
      id: job.id,
      data: job.data as unknown,
      opts: job.opts,
      timestamp: job.timestamp,
      delay: job.opts.delay,
    }));
  }

  /**
   * 특정 작업 상세 조회
   */
  @Get('jobs/:jobId')
  @ApiOperation({ summary: '특정 작업 상세 정보 조회' })
  @ApiResponse({ status: 200, description: '작업 상세 정보' })
  @ApiResponse({ status: 404, description: '작업을 찾을 수 없음' })
  async getJobDetails(@Param('jobId') jobId: string) {
    const job = await this.emailQueue.getJob(jobId);
    if (!job) {
      return { error: 'Job not found' };
    }

    return {
      id: job.id,
      name: job.name,
      data: job.data as unknown,
      opts: job.opts,
      timestamp: job.timestamp,
      processedOn: job.processedOn,
      finishedOn: job.finishedOn,
      progress: job.progress() as unknown,
      failedReason: job.failedReason,
      stacktrace: job.stacktrace,
      attemptsMade: job.attemptsMade,
      delay: job.opts.delay,
      returnvalue: job.returnvalue as unknown,
    };
  }

  /**
   * 실패한 작업들 재시도
   */
  @Post('retry-failed')
  @ApiOperation({ summary: '실패한 작업들 재시도' })
  @ApiResponse({ status: 200, description: '재시도된 작업 수' })
  async retryFailedJobs(@Query('limit') limit = 10) {
    const retriedCount = await this.emailQueueService.retryFailedJobs(limit);
    return { retriedCount };
  }

  /**
   * 특정 작업 재시도
   */
  @Post('jobs/:jobId/retry')
  @ApiOperation({ summary: '특정 작업 재시도' })
  @ApiResponse({ status: 200, description: '작업 재시도 성공' })
  @ApiResponse({ status: 404, description: '작업을 찾을 수 없음' })
  async retryJob(@Param('jobId') jobId: string) {
    const job = await this.emailQueue.getJob(jobId);
    if (!job) {
      return { error: 'Job not found' };
    }

    await job.retry();
    return { message: 'Job retried successfully' };
  }

  /**
   * 특정 작업 제거
   */
  @Delete('jobs/:jobId')
  @ApiOperation({ summary: '특정 작업 제거' })
  @ApiResponse({ status: 200, description: '작업 제거 성공' })
  @ApiResponse({ status: 404, description: '작업을 찾을 수 없음' })
  async removeJob(@Param('jobId') jobId: string) {
    const removed = await this.emailQueueService.removeJob(jobId);
    return removed
      ? { message: 'Job removed successfully' }
      : { error: 'Job not found or could not be removed' };
  }

  /**
   * 큐 일시정지
   */
  @Post('pause')
  @ApiOperation({ summary: '큐 일시정지' })
  @ApiResponse({ status: 200, description: '큐 일시정지 성공' })
  async pauseQueue() {
    await this.emailQueueService.pauseQueue();
    return { message: 'Queue paused successfully' };
  }

  /**
   * 큐 재개
   */
  @Post('resume')
  @ApiOperation({ summary: '큐 재개' })
  @ApiResponse({ status: 200, description: '큐 재개 성공' })
  async resumeQueue() {
    await this.emailQueueService.resumeQueue();
    return { message: 'Queue resumed successfully' };
  }

  /**
   * 큐 정리 (완료/실패한 작업 제거)
   */
  @Post('clean')
  @ApiOperation({ summary: '큐 정리 (완료/실패한 작업 제거)' })
  @ApiResponse({ status: 200, description: '큐 정리 성공' })
  async cleanQueue(
    @Query('grace') grace = 86400000, // 24시간 후 정리 (디버깅을 위한 기록 보존)
    @Query('limit') limit = 1000,
  ) {
    const result = await this.emailQueueService.cleanQueue(grace, limit);
    return {
      message: 'Queue cleaned successfully',
      cleanedCompleted: result.cleanedCompleted,
      cleanedFailed: result.cleanedFailed,
      totalCleaned: result.cleanedCompleted + result.cleanedFailed,
    };
  }

  /**
   * 큐의 모든 작업 제거 (주의!)
   */
  @Delete('purge')
  @ApiOperation({
    summary: '큐의 모든 작업 제거',
    description: '주의: 이 작업은 되돌릴 수 없습니다!',
  })
  @ApiResponse({ status: 200, description: '큐 비우기 성공' })
  @ApiResponse({ status: 401, description: '인증이 필요합니다' })
  @ApiResponse({ status: 403, description: '관리자 권한이 필요합니다' })
  async purgeQueue() {
    await this.emailQueueService.purgeQueue();
    return { message: 'All jobs purged from queue' };
  }

  /**
   * 큐 일반 정보 조회
   */
  @Get('info')
  @ApiOperation({ summary: '큐 일반 정보 조회' })
  @ApiResponse({ status: 200, description: '큐 정보' })
  async getQueueInfo() {
    const isPaused = await this.emailQueue.isPaused();
    const name = this.emailQueue.name;

    return {
      name,
      isPaused,
      redis: {
        host: this.emailQueue.client.options.host,
        port: this.emailQueue.client.options.port,
        db: this.emailQueue.client.options.db,
      },
    };
  }

  /**
   * 큐 대시보드 - 모든 정보를 한 번에 조회
   */
  @Get('dashboard')
  @ApiOperation({ summary: '큐 대시보드 - 전체 상태 조회' })
  @ApiResponse({ status: 200, description: '큐 전체 상태 정보' })
  async getDashboard() {
    const stats = await this.emailQueueService.getQueueStats();
    const isPaused = await this.emailQueue.isPaused();

    // 최근 작업들 (각각 최대 3개씩)
    const recentWaiting = await this.emailQueue.getWaiting(0, 3);
    const recentActive = await this.emailQueue.getActive();
    const recentCompleted = await this.emailQueue.getCompleted(0, 3);
    const recentFailed = await this.emailQueue.getFailed(0, 3);

    return {
      queueName: this.emailQueue.name,
      isPaused,
      timestamp: new Date().toISOString(),
      stats,
      recent: {
        waiting: recentWaiting.map((job) => ({
          id: job.id,
          type: job.name,
          createdAt: new Date(job.timestamp).toISOString(),
        })),
        active: recentActive.map((job) => ({
          id: job.id,
          type: job.name,
          startedAt: job.processedOn
            ? new Date(job.processedOn).toISOString()
            : null,
        })),
        completed: recentCompleted.map((job) => ({
          id: job.id,
          type: job.name,
          completedAt: job.finishedOn
            ? new Date(job.finishedOn).toISOString()
            : null,
        })),
        failed: recentFailed.map((job) => ({
          id: job.id,
          type: job.name,
          failedAt: job.finishedOn
            ? new Date(job.finishedOn).toISOString()
            : null,
          error: job.failedReason,
          attempts: job.attemptsMade,
        })),
      },
      redis: {
        host: this.emailQueue.client.options.host,
        port: this.emailQueue.client.options.port,
        db: this.emailQueue.client.options.db,
        status: this.emailQueue.client.status,
      },
    };
  }

  /**
   * 큐 헬스 체크 - 간단한 상태 확인
   */
  @Get('health')
  @ApiOperation({ summary: '큐 헬스 체크' })
  @ApiResponse({ status: 200, description: '큐 상태 확인' })
  async getHealth() {
    try {
      const stats = await this.emailQueueService.getQueueStats();
      const isPaused = await this.emailQueue.isPaused();
      const redisStatus = this.emailQueue.client.status;

      const isHealthy = redisStatus === 'ready' && !isPaused;

      return {
        status: isHealthy ? 'healthy' : 'degraded',
        queue: {
          name: this.emailQueue.name,
          isPaused,
          totalJobs:
            stats.waiting +
            stats.active +
            stats.completed +
            stats.failed +
            stats.delayed,
        },
        redis: {
          status: redisStatus,
          connected: redisStatus === 'ready',
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error: unknown) {
      return {
        status: 'unhealthy',
        error: (error as Error).message,
        timestamp: new Date().toISOString(),
      };
    }
  }
}
