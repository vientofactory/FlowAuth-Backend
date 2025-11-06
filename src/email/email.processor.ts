import { Process, Processor } from '@nestjs/bull';
import { Injectable, Logger } from '@nestjs/common';
import { Job } from 'bull';
import { EmailService } from './email.service';
import {
  EmailJobPayload,
  EmailJobType,
  WelcomeEmailJobPayload,
  EmailVerificationJobPayload,
  PasswordResetJobPayload,
  SecurityAlertJobPayload,
  TwoFAEnabledJobPayload,
  ClientCreatedJobPayload,
  TemplateEmailJobPayload,
} from './interfaces/email-job.interface';

/**
 * 이메일 큐 프로세서
 * Bull Queue를 사용하여 이메일 작업을 비동기적으로 처리합니다.
 */
@Injectable()
@Processor('email')
export class EmailProcessor {
  private readonly logger = new Logger(EmailProcessor.name);

  constructor(private readonly emailService: EmailService) {}

  /**
   * 환영 이메일 처리
   */
  @Process(EmailJobType.WELCOME)
  async processWelcomeEmail(job: Job<WelcomeEmailJobPayload>): Promise<void> {
    const { to, username } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(`Processing welcome email job ${job.id} for ${to}`);
    }

    try {
      await this.emailService.sendWelcomeEmail(to, username);

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Welcome email sent successfully to ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to send welcome email to ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error; // Bull Queue가 재시도를 처리합니다
    }
  }

  /**
   * 이메일 인증 처리
   */
  @Process(EmailJobType.EMAIL_VERIFICATION)
  async processEmailVerification(
    job: Job<EmailVerificationJobPayload>,
  ): Promise<void> {
    const { to, username, verificationToken } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(
        `Processing email verification job ${job.id} for ${to}`,
      );
    }

    try {
      await this.emailService.sendEmailVerification(
        to,
        username,
        verificationToken,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Email verification sent successfully to ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to send email verification to ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 비밀번호 재설정 처리
   */
  @Process(EmailJobType.PASSWORD_RESET)
  async processPasswordReset(job: Job<PasswordResetJobPayload>): Promise<void> {
    const { to, username, resetToken } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(`Processing password reset job ${job.id} for ${to}`);
    }

    try {
      await this.emailService.sendPasswordReset(to, username, resetToken);

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Password reset email sent successfully to ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 보안 알림 처리
   */
  @Process(EmailJobType.SECURITY_ALERT)
  async processSecurityAlert(job: Job<SecurityAlertJobPayload>): Promise<void> {
    const { to, username, alertType, details } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(`Processing security alert job ${job.id} for ${to}`);
    }

    try {
      await this.emailService.sendSecurityAlert(
        to,
        username,
        alertType,
        details,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Security alert email sent successfully to ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to send security alert email to ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 2FA 활성화 알림 처리
   */
  @Process(EmailJobType.TWO_FA_ENABLED)
  async processTwoFAEnabled(job: Job<TwoFAEnabledJobPayload>): Promise<void> {
    const { to, username } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(`Processing 2FA enabled job ${job.id} for ${to}`);
    }

    try {
      await this.emailService.send2FAEnabled(to, username);

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `2FA enabled notification sent successfully to ${to}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to send 2FA enabled notification to ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * OAuth2 클라이언트 생성 알림 처리
   */
  @Process(EmailJobType.CLIENT_CREATED)
  async processClientCreated(job: Job<ClientCreatedJobPayload>): Promise<void> {
    const { to, username, clientName, clientId } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(`Processing client created job ${job.id} for ${to}`);
    }

    try {
      await this.emailService.sendClientCreated(
        to,
        username,
        clientName,
        clientId,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `Client created notification sent successfully to ${to}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to send client created notification to ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 템플릿 이메일 처리 (범용)
   */
  @Process(EmailJobType.TEMPLATE_EMAIL)
  async processTemplateEmail(job: Job<TemplateEmailJobPayload>): Promise<void> {
    const { to, subject, templateName, context } = job.data;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(
        `Processing template email job ${job.id} for ${to} with template ${templateName}`,
      );
    }

    try {
      await this.emailService.sendTemplateEmail({
        to,
        subject,
        templateName,
        context,
      });

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `Template email sent successfully to ${to} using ${templateName}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to send template email to ${to} using ${templateName}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 작업 완료 이벤트 핸들러
   */
  onCompleted(job: Job<EmailJobPayload>): void {
    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(`Email job ${job.id} completed successfully`);
    }
  }

  /**
   * 작업 실패 이벤트 핸들러
   */
  onFailed(job: Job<EmailJobPayload>, error: Error): void {
    this.logger.error(
      `Email job ${job.id} failed after ${job.attemptsMade} attempts`,
      error.stack,
    );

    // 중요한 이메일의 경우 별도 알림을 보낼 수 있습니다
    const criticalTypes = [
      EmailJobType.EMAIL_VERIFICATION,
      EmailJobType.PASSWORD_RESET,
      EmailJobType.SECURITY_ALERT,
    ];

    if (
      criticalTypes.includes(job.data.type) &&
      job.attemptsMade >= (job.opts.attempts ?? 3)
    ) {
      this.logger.error(
        `Critical email job ${job.id} permanently failed for ${job.data.to}`,
      );
      // 여기에서 관리자 알림, Slack 메시지 등을 보낼 수 있습니다
    }
  }

  /**
   * 작업 진행 이벤트 핸들러
   */
  onProgress(job: Job<EmailJobPayload>, progress: number): void {
    this.logger.debug(`Email job ${job.id} progress: ${progress}%`);
  }

  /**
   * 작업 정체 이벤트 핸들러
   */
  onStalled(job: Job<EmailJobPayload>): void {
    if (process.env.NODE_ENV === 'development') {
      this.logger.warn(`Email job ${job.id} stalled`);
    }
  }
}
