import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue, Job } from 'bull';
import {
  EmailJobPayload,
  EmailJobType,
  EmailJobOptions,
  EMAIL_JOB_CONFIGS,
  EMAIL_PRIORITY,
  WelcomeEmailJobPayload,
  EmailVerificationJobPayload,
  PasswordResetJobPayload,
  SecurityAlertJobPayload,
  TwoFAEnabledJobPayload,
  ClientCreatedJobPayload,
  TemplateEmailJobPayload,
} from './interfaces/email-job.interface';

/**
 * 이메일 큐 서비스
 * Bull Queue를 사용하여 이메일 작업을 관리합니다.
 */
@Injectable()
export class EmailQueueService {
  private readonly logger = new Logger(EmailQueueService.name);

  constructor(
    @InjectQueue('email')
    private readonly emailQueue: Queue,
  ) {}

  /**
   * 작업 타입에 따른 기본 설정 조회
   */
  private getJobConfig(jobType: EmailJobType): EmailJobOptions {
    switch (jobType) {
      case EmailJobType.WELCOME:
        return EMAIL_JOB_CONFIGS[EmailJobType.WELCOME];
      case EmailJobType.EMAIL_VERIFICATION:
        return EMAIL_JOB_CONFIGS[EmailJobType.EMAIL_VERIFICATION];
      case EmailJobType.PASSWORD_RESET:
        return EMAIL_JOB_CONFIGS[EmailJobType.PASSWORD_RESET];
      case EmailJobType.SECURITY_ALERT:
        return EMAIL_JOB_CONFIGS[EmailJobType.SECURITY_ALERT];
      case EmailJobType.TWO_FA_ENABLED:
        return EMAIL_JOB_CONFIGS[EmailJobType.TWO_FA_ENABLED];
      case EmailJobType.CLIENT_CREATED:
        return EMAIL_JOB_CONFIGS[EmailJobType.CLIENT_CREATED];
      case EmailJobType.TEMPLATE_EMAIL:
        return EMAIL_JOB_CONFIGS[EmailJobType.TEMPLATE_EMAIL];
      default:
        return EMAIL_JOB_CONFIGS[EmailJobType.TEMPLATE_EMAIL];
    }
  }

  /**
   * 큐에 이메일 작업 추가
   */
  private async addJobToQueue<T extends EmailJobPayload>(
    jobType: EmailJobType,
    jobData: T,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      // 기본 설정과 사용자 설정 병합
      const defaultConfig = this.getJobConfig(jobType);
      const finalOptions = {
        ...defaultConfig,
        ...options,
      };

      // 작업을 큐에 추가
      const job = await this.emailQueue.add(jobType, jobData, finalOptions);

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `Email job ${job.id} added to queue: ${jobType} for ${jobData.to}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to add email job to queue: ${jobType} for ${jobData.to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 환영 이메일 큐에 추가
   */
  async addWelcomeEmailJob(
    to: string,
    username: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: WelcomeEmailJobPayload = {
      type: EmailJobType.WELCOME,
      to,
      username,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.WELCOME, jobData, options);
  }

  /**
   * 이메일 인증 큐에 추가
   */
  async addEmailVerificationJob(
    to: string,
    username: string,
    verificationToken: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: EmailVerificationJobPayload = {
      type: EmailJobType.EMAIL_VERIFICATION,
      to,
      username,
      verificationToken,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.EMAIL_VERIFICATION, jobData, {
      ...options,
      priority: EMAIL_PRIORITY.HIGH, // 인증 이메일은 높은 우선순위
    });
  }

  /**
   * 비밀번호 재설정 큐에 추가
   */
  async addPasswordResetJob(
    to: string,
    username: string,
    resetToken: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: PasswordResetJobPayload = {
      type: EmailJobType.PASSWORD_RESET,
      to,
      username,
      resetToken,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.PASSWORD_RESET, jobData, {
      ...options,
      priority: EMAIL_PRIORITY.HIGH, // 비밀번호 재설정은 높은 우선순위
    });
  }

  /**
   * 보안 알림 큐에 추가
   */
  async addSecurityAlertJob(
    to: string,
    username: string,
    alertType: string,
    details: { [key: string]: unknown },
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: SecurityAlertJobPayload = {
      type: EmailJobType.SECURITY_ALERT,
      to,
      username,
      alertType,
      details,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.SECURITY_ALERT, jobData, {
      ...options,
      priority: EMAIL_PRIORITY.CRITICAL, // 보안 알림은 최고 우선순위
    });
  }

  /**
   * 2FA 활성화 알림 큐에 추가
   */
  async addTwoFAEnabledJob(
    to: string,
    username: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: TwoFAEnabledJobPayload = {
      type: EmailJobType.TWO_FA_ENABLED,
      to,
      username,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.TWO_FA_ENABLED, jobData, {
      ...options,
      priority: EMAIL_PRIORITY.HIGH,
    });
  }

  /**
   * OAuth2 클라이언트 생성 알림 큐에 추가
   */
  async addClientCreatedJob(
    to: string,
    username: string,
    clientName: string,
    clientId: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: ClientCreatedJobPayload = {
      type: EmailJobType.CLIENT_CREATED,
      to,
      username,
      clientName,
      clientId,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.CLIENT_CREATED, jobData, options);
  }

  /**
   * 템플릿 이메일 큐에 추가 (범용)
   */
  async addTemplateEmailJob(
    to: string,
    subject: string,
    templateName: string,
    context: { [key: string]: unknown },
    options?: EmailJobOptions,
  ): Promise<void> {
    const jobData: TemplateEmailJobPayload = {
      type: EmailJobType.TEMPLATE_EMAIL,
      to,
      subject,
      templateName,
      context,
      ...options,
    };

    await this.addJobToQueue(EmailJobType.TEMPLATE_EMAIL, jobData, options);
  }

  /**
   * 지연된 이메일 전송
   */
  async addDelayedEmailJob<T extends EmailJobPayload>(
    jobType: EmailJobType,
    jobData: T,
    delayInMs: number,
    options?: EmailJobOptions,
  ): Promise<void> {
    await this.addJobToQueue(jobType, jobData, {
      ...options,
      delay: delayInMs,
    });
  }

  /**
   * 반복 이메일 작업 (예: 주기적 리포트)
   */
  async addRepeatingEmailJob<T extends EmailJobPayload>(
    jobType: EmailJobType,
    jobData: T,
    cronExpression: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      const defaultConfig = this.getJobConfig(jobType);
      await this.emailQueue.add(jobType, jobData, {
        ...defaultConfig,
        ...options,
        repeat: { cron: cronExpression },
      });

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `Repeating email job added: ${jobType} with cron ${cronExpression}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to add repeating email job: ${jobType}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 큐 상태 조회
   */
  async getQueueStats(): Promise<{
    active: number;
    waiting: number;
    completed: number;
    failed: number;
    delayed: number;
    paused: number;
  }> {
    const [active, waiting, completed, failed, delayed, paused] =
      await Promise.all([
        this.emailQueue.getActive(),
        this.emailQueue.getWaiting(),
        this.emailQueue.getCompleted(),
        this.emailQueue.getFailed(),
        this.emailQueue.getDelayed(),
        this.emailQueue.isPaused(),
      ]);

    return {
      active: active.length,
      waiting: waiting.length,
      completed: completed.length,
      failed: failed.length,
      delayed: delayed.length,
      paused: paused ? 1 : 0,
    };
  }

  /**
   * 실패한 작업 재시도
   */
  async retryFailedJobs(limit = 10): Promise<number> {
    try {
      const failedJobs = await this.emailQueue.getFailed(0, limit - 1);
      let retriedCount = 0;

      for (const job of failedJobs) {
        try {
          await job.retry();
          retriedCount++;

          if (process.env.NODE_ENV === 'development') {
            this.logger.debug(`Retried failed email job ${job.id}`);
          }
        } catch (error) {
          this.logger.error(
            `Failed to retry job ${job.id}`,
            error instanceof Error ? error.stack : undefined,
          );
        }
      }

      // 재시도 결과는 운영상 중요한 정보이므로 항상 로그 출력
      this.logger.log(`Retried ${retriedCount} failed email jobs`);
      return retriedCount;
    } catch (error) {
      this.logger.error(
        'Failed to retry failed jobs',
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 큐 정리 (완료된/실패한 작업 제거)
   */
  async cleanQueue(
    grace = 24 * 60 * 60 * 1000, // 24시간 후 정리 (디버깅을 위한 충분한 시간 제공)
    limit = 1000,
  ): Promise<{ cleanedCompleted: number; cleanedFailed: number }> {
    try {
      const [completedJobs, failedJobs] = await Promise.all([
        this.emailQueue.clean(grace, 'completed', limit),
        this.emailQueue.clean(grace, 'failed', limit),
      ]);

      const cleanedCompleted = completedJobs.length;
      const cleanedFailed = failedJobs.length;

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `Cleaned email queue: removed ${cleanedCompleted} completed and ${cleanedFailed} failed jobs`,
        );
      }

      return { cleanedCompleted, cleanedFailed };
    } catch (error) {
      this.logger.error(
        'Failed to clean email queue',
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 큐 일시정지
   */
  async pauseQueue(): Promise<void> {
    await this.emailQueue.pause();

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug('Email queue paused');
    }
  }

  /**
   * 큐 재개
   */
  async resumeQueue(): Promise<void> {
    await this.emailQueue.resume();

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug('Email queue resumed');
    }
  }

  /**
   * 특정 작업 제거
   */
  async removeJob(jobId: string): Promise<boolean> {
    try {
      const job = await this.emailQueue.getJob(jobId);
      if (job) {
        await job.remove();

        if (process.env.NODE_ENV === 'development') {
          this.logger.debug(`Removed email job ${jobId}`);
        }

        return true;
      }
      return false;
    } catch (error) {
      this.logger.error(
        `Failed to remove job ${jobId}`,
        error instanceof Error ? error.stack : undefined,
      );
      return false;
    }
  }

  /**
   * 큐의 모든 작업 제거 (주의!)
   */
  async purgeQueue(): Promise<void> {
    try {
      await this.emailQueue.clean(0, 'completed');
      await this.emailQueue.clean(0, 'failed');
      await this.emailQueue.clean(0, 'active');
      await this.emailQueue.clean(0, 'delayed');

      this.logger.warn('Email queue purged - all jobs removed');
    } catch {
      // fallback to empty() if clean() is not available
      try {
        await this.emailQueue.empty();
        this.logger.warn(
          'Email queue purged using fallback method - all jobs removed',
        );
      } catch (emptyError) {
        this.logger.error(
          'Failed to purge email queue',
          emptyError instanceof Error ? emptyError.stack : undefined,
        );
        throw emptyError;
      }
    }
  }

  /**
   * Graceful shutdown을 위한 큐 종료
   * 진행 중인 작업을 완료하고 새로운 작업은 받지 않음
   */
  async gracefulShutdown(timeout = 30000): Promise<void> {
    this.logger.log('Starting graceful shutdown of email queue...');

    try {
      // 새로운 작업 추가 방지를 위해 큐 일시정지
      await this.pauseQueue();

      // 활성 작업 수 확인
      const activeJobs = await this.emailQueue.getActive();
      if (activeJobs.length > 0) {
        this.logger.log(
          `Waiting for ${activeJobs.length} active email jobs to complete...`,
        );

        // 활성 작업이 완료될 때까지 대기 (타임아웃과 함께)
        await this.waitForJobsToComplete(activeJobs, timeout);
      }

      // 큐 연결 종료
      await this.emailQueue.close();
      this.logger.log('Email queue closed successfully');
    } catch (error) {
      this.logger.error(
        'Error during email queue graceful shutdown',
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 활성 작업들이 완료될 때까지 대기
   */
  private async waitForJobsToComplete(
    _activeJobs: Job[],
    timeout: number,
  ): Promise<void> {
    const startTime = Date.now();

    return new Promise<void>((resolve, reject) => {
      const checkInterval = setInterval(() => {
        void (async (): Promise<void> => {
          try {
            const currentActiveJobs = await this.emailQueue.getActive();
            const elapsed = Date.now() - startTime;

            if (currentActiveJobs.length === 0) {
              clearInterval(checkInterval);
              this.logger.log('All email jobs completed successfully');
              resolve();
            } else if (elapsed >= timeout) {
              clearInterval(checkInterval);
              this.logger.warn(
                `Timeout reached. ${currentActiveJobs.length} email jobs still active after ${timeout}ms`,
              );

              // 타임아웃 시 남은 작업들을 처리
              await this.handleRemainingJobs(currentActiveJobs);
              resolve();
            } else {
              this.logger.debug(
                `Waiting for ${currentActiveJobs.length} email jobs to complete (${elapsed}ms elapsed)`,
              );
            }
          } catch (error) {
            clearInterval(checkInterval);
            reject(
              error instanceof Error
                ? error
                : new Error('Unknown error during job completion check'),
            );
          }
        })();
      }, 1000); // 1초마다 체크
    });
  }

  /**
   * 타임아웃 시 남은 작업들을 처리
   */
  private async handleRemainingJobs(remainingJobs: Job[]): Promise<void> {
    this.logger.log(`Handling ${remainingJobs.length} remaining email jobs...`);

    for (const job of remainingJobs) {
      try {
        // Bull 큐의 Job은 moveToWaiting 메서드가 없으므로 discard를 사용
        await job.discard();
        this.logger.debug(`Discarded job ${job.id}`);
      } catch (error) {
        this.logger.error(
          `Failed to handle job ${job.id}`,
          error instanceof Error ? error.stack : undefined,
        );
      }
    }
  }

  /**
   * 큐 상태 확인 (헬스체크용)
   */
  async isHealthy(): Promise<boolean> {
    try {
      // Redis 연결 상태 확인
      await this.getQueueStats();
      return true;
    } catch (error) {
      this.logger.error('Email queue health check failed', error);
      return false;
    }
  }

  /**
   * 현재 진행 중인 작업 목록 조회 (디버깅용)
   */
  async getActiveJobs(): Promise<
    Array<{ id: string; type: string; progress: number }>
  > {
    try {
      const activeJobs = await this.emailQueue.getActive();
      return activeJobs.map((job) => ({
        id: job.id?.toString() ?? 'unknown',
        type: job.name,
        progress: (job.progress() as number) || 0,
      }));
    } catch (error) {
      this.logger.error('Failed to get active jobs', error);
      return [];
    }
  }

  /**
   * 큐 이름 반환 (로깅/모니터링용)
   */
  getQueueName(): string {
    return this.emailQueue.name;
  }

  /**
   * 큐가 일시정지된 상태인지 확인
   */
  async isPaused(): Promise<boolean> {
    try {
      return await this.emailQueue.isPaused();
    } catch (error) {
      this.logger.error('Failed to check queue pause status', error);
      return false;
    }
  }
}
