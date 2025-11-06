import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import { readFileSync } from 'fs';
import { join } from 'path';
import { EmailQueueService } from './email-queue.service';
import { EmailJobOptions } from './interfaces/email-job.interface';

export interface EmailContext {
  [key: string]: unknown;
}

export interface EmailOptions {
  to: string;
  subject: string;
  templateName: string;
  context: EmailContext;
}

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(
    private configService: ConfigService,
    private emailQueueService: EmailQueueService,
  ) {
    this.initializeTransporter();
  }

  private initializeTransporter(): void {
    const smtpConfig = {
      host: this.configService.get<string>('SMTP_HOST'),
      port: this.configService.get<number>('SMTP_PORT', 587),
      secure: Boolean(this.configService.get<number>('SMTP_SECURE', 0)),
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_PASS'),
      },
    };

    this.transporter = nodemailer.createTransport(smtpConfig);

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug('SMTP transporter initialized');
    }
  }

  /**
   * 허용된 템플릿 이름 목록
   */
  private readonly allowedTemplates = [
    'welcome',
    'email-verification',
    'password-reset',
    'security-alert',
    '2fa-enabled',
    'client-created',
  ] as const;

  /**
   * 템플릿 경로를 동적으로 생성
   */
  private getTemplatePath(templateName: string): string | null {
    // 보안 검증: 허용된 템플릿만 사용
    type AllowedTemplate = (typeof this.allowedTemplates)[number];
    if (!this.allowedTemplates.includes(templateName as AllowedTemplate)) {
      return null;
    }

    const isDevelopment = process.env.NODE_ENV === 'development';
    const baseDir = isDevelopment ? 'src' : 'dist';

    return join(
      process.cwd(),
      baseDir,
      'email',
      'templates',
      `${templateName}.hbs`,
    );
  }

  /**
   * 템플릿을 사용하여 이메일 전송
   */
  async sendTemplateEmail(options: EmailOptions): Promise<void> {
    try {
      const { to, subject, templateName, context } = options;

      // 템플릿 경로 조회 (보안 검증 포함)
      const templatePath = this.getTemplatePath(templateName);
      if (!templatePath) {
        throw new Error(`Invalid template name: ${templateName}`);
      }

      // 템플릿 파일 읽기
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const templateSource = readFileSync(templatePath, 'utf8');
      const template = handlebars.compile(templateSource);

      // 템플릿에 데이터 적용
      const html = template({
        ...context,
        appName: this.configService.get<string>('APP_NAME', 'FlowAuth'),
        appUrl: this.configService.get<string>('APP_URL'),
        supportEmail: this.configService.get<string>('SUPPORT_EMAIL'),
        year: new Date().getFullYear(),
      });

      // 이메일 전송
      await this.transporter.sendMail({
        from: this.configService.get<string>('SMTP_FROM'),
        to,
        subject,
        html,
      });

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(
          `Email sent successfully to ${to} using template ${templateName}`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to send email to ${options.to}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 회원가입 환영 이메일 전송
   */
  async sendWelcomeEmail(to: string, username: string): Promise<void> {
    await this.sendTemplateEmail({
      to,
      subject: '환영합니다! FlowAuth 회원가입이 완료되었습니다.',
      templateName: 'welcome',
      context: {
        username,
        loginUrl: `${this.configService.get<string>('FRONTEND_URL')}/auth/login`,
      },
    });
  }

  /**
   * 이메일 인증 메일 전송
   */
  async sendEmailVerification(
    to: string,
    username: string,
    verificationToken: string,
  ): Promise<void> {
    const verificationUrl = `${this.configService.get<string>(
      'FRONTEND_URL',
    )}/auth/verify-email?token=${verificationToken}`;

    await this.sendTemplateEmail({
      to,
      subject: 'FlowAuth 이메일 주소를 인증해주세요',
      templateName: 'email-verification',
      context: {
        username,
        verificationUrl,
        expiryHours: 24,
      },
    });
  }

  /**
   * 비밀번호 재설정 이메일 전송
   */
  async sendPasswordReset(
    to: string,
    username: string,
    resetToken: string,
  ): Promise<void> {
    const resetUrl = `${this.configService.get<string>(
      'FRONTEND_URL',
    )}/auth/reset-password?token=${resetToken}`;

    await this.sendTemplateEmail({
      to,
      subject: 'FlowAuth 비밀번호 재설정',
      templateName: 'password-reset',
      context: {
        username,
        resetUrl,
        expiryHours: 1,
      },
    });
  }

  /**
   * 보안 알림 이메일 전송 (로그인, 비밀번호 변경 등)
   */
  async sendSecurityAlert(
    to: string,
    username: string,
    alertType: string,
    details: { [key: string]: unknown },
  ): Promise<void> {
    await this.sendTemplateEmail({
      to,
      subject: `FlowAuth 보안 알림: ${alertType}`,
      templateName: 'security-alert',
      context: {
        username,
        alertType,
        ...details,
        timestamp: new Date().toLocaleString('ko-KR'),
      },
    });
  }

  /**
   * 2FA 설정 완료 알림
   */
  async send2FAEnabled(to: string, username: string): Promise<void> {
    await this.sendTemplateEmail({
      to,
      subject: 'FlowAuth 2단계 인증이 활성화되었습니다',
      templateName: '2fa-enabled',
      context: {
        username,
        timestamp: new Date().toLocaleString('ko-KR'),
      },
    });
  }

  /**
   * OAuth2 클라이언트 생성 알림
   */
  async sendClientCreated(
    to: string,
    username: string,
    clientName: string,
    clientId: string,
  ): Promise<void> {
    await this.sendTemplateEmail({
      to,
      subject: `새로운 OAuth2 클라이언트가 생성되었습니다: ${clientName}`,
      templateName: 'client-created',
      context: {
        username,
        clientName,
        clientId,
        timestamp: new Date().toLocaleString('ko-KR'),
        dashboardUrl: `${this.configService.get<string>('FRONTEND_URL')}/dashboard`,
      },
    });
  }

  /**
   * 트랜스포터 연결 테스트
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug('SMTP connection test successful');
      }

      return true;
    } catch (error) {
      this.logger.error(
        'SMTP connection test failed',
        error instanceof Error ? error.stack : undefined,
      );
      return false;
    }
  }

  /**
   * SMTP 연결 정보 및 상태 조회
   */
  async getSmtpInfo(): Promise<{
    connected: boolean;
    host: string;
    port: number;
    auth: string;
    secure: boolean;
    lastChecked: string;
  }> {
    const host = this.configService.get<string>('SMTP_HOST', 'localhost');
    const port = this.configService.get<number>('SMTP_PORT', 587);
    const secure = Boolean(this.configService.get<number>('SMTP_SECURE', 0));
    const user = this.configService.get<string>('SMTP_USER', '');

    let connected = false;
    try {
      connected = await this.testConnection();
    } catch (error) {
      this.logger.error('Failed to test SMTP connection for info', error);
    }

    return {
      connected,
      host,
      port,
      auth: user ? `${user.substring(0, 3)}***` : '없음',
      secure,
      lastChecked: new Date().toISOString(),
    };
  }

  // === 큐 기반 비동기 이메일 전송 메서드들 ===

  /**
   * 환영 이메일을 큐에 추가하여 비동기 전송
   */
  async queueWelcomeEmail(
    to: string,
    username: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addWelcomeEmailJob(to, username, options);

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Welcome email queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue welcome email for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 이메일 인증을 큐에 추가하여 비동기 전송
   */
  async queueEmailVerification(
    to: string,
    username: string,
    verificationToken: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addEmailVerificationJob(
        to,
        username,
        verificationToken,
        options,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Email verification queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue email verification for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 비밀번호 재설정을 큐에 추가하여 비동기 전송
   */
  async queuePasswordReset(
    to: string,
    username: string,
    resetToken: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addPasswordResetJob(
        to,
        username,
        resetToken,
        options,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Password reset email queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue password reset email for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 보안 알림을 큐에 추가하여 비동기 전송
   */
  async queueSecurityAlert(
    to: string,
    username: string,
    alertType: string,
    details: { [key: string]: unknown },
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addSecurityAlertJob(
        to,
        username,
        alertType,
        details,
        options,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Security alert email queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue security alert email for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 2FA 활성화 알림을 큐에 추가하여 비동기 전송
   */
  async queue2FAEnabled(
    to: string,
    username: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addTwoFAEnabledJob(to, username, options);

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`2FA enabled notification queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue 2FA enabled notification for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 클라이언트 생성 알림을 큐에 추가하여 비동기 전송
   */
  async queueClientCreated(
    to: string,
    username: string,
    clientName: string,
    clientId: string,
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addClientCreatedJob(
        to,
        username,
        clientName,
        clientId,
        options,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Client created notification queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue client created notification for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 템플릿 이메일을 큐에 추가하여 비동기 전송
   */
  async queueTemplateEmail(
    to: string,
    subject: string,
    templateName: string,
    context: { [key: string]: unknown },
    options?: EmailJobOptions,
  ): Promise<void> {
    try {
      await this.emailQueueService.addTemplateEmailJob(
        to,
        subject,
        templateName,
        context,
        options,
      );

      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Template email (${templateName}) queued for ${to}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue template email (${templateName}) for ${to}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  /**
   * 지연된 이메일 전송을 큐에 추가
   */
  async queueDelayedEmail(
    emailType:
      | 'welcome'
      | 'verification'
      | 'password-reset'
      | 'security-alert'
      | '2fa-enabled'
      | 'client-created',
    emailData: Record<string, unknown>,
    delayInMs: number,
    options?: EmailJobOptions,
  ): Promise<void> {
    const { to } = emailData;

    if (process.env.NODE_ENV === 'development') {
      this.logger.debug(
        `Delayed ${emailType} email queued for ${String(to)} (delay: ${delayInMs}ms)`,
      );
    }

    try {
      switch (emailType) {
        case 'welcome':
          await this.queueWelcomeEmail(
            emailData.to as string,
            emailData.username as string,
            { ...options, delay: delayInMs },
          );
          break;
        case 'verification':
          await this.queueEmailVerification(
            emailData.to as string,
            emailData.username as string,
            emailData.verificationToken as string,
            { ...options, delay: delayInMs },
          );
          break;
        case 'password-reset':
          await this.queuePasswordReset(
            emailData.to as string,
            emailData.username as string,
            emailData.resetToken as string,
            { ...options, delay: delayInMs },
          );
          break;
        case 'security-alert':
          await this.queueSecurityAlert(
            emailData.to as string,
            emailData.username as string,
            emailData.alertType as string,
            emailData.details as { [key: string]: unknown },
            { ...options, delay: delayInMs },
          );
          break;
        case '2fa-enabled':
          await this.queue2FAEnabled(
            emailData.to as string,
            emailData.username as string,
            { ...options, delay: delayInMs },
          );
          break;
        case 'client-created':
          await this.queueClientCreated(
            emailData.to as string,
            emailData.username as string,
            emailData.clientName as string,
            emailData.clientId as string,
            { ...options, delay: delayInMs },
          );
          break;
        default:
          throw new Error(`Unknown email type: ${String(emailType)}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to queue delayed ${emailType} email`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }
  }

  // === 레거시 비동기 메서드들 (하위 호환성 유지) ===

  /**
   * @deprecated 큐 기반 메서드 사용 권장: queueWelcomeEmail
   */
  sendWelcomeEmailAsync(to: string, username: string): void {
    this.queueWelcomeEmail(to, username).catch((error) => {
      this.logger.error('Failed to queue welcome email', error);
    });
  }

  /**
   * @deprecated 큐 기반 메서드 사용 권장: queueEmailVerification
   */
  sendEmailVerificationAsync(
    to: string,
    username: string,
    verificationToken: string,
  ): void {
    this.queueEmailVerification(to, username, verificationToken).catch(
      (error) => {
        this.logger.error('Failed to queue email verification', error);
      },
    );
  }

  /**
   * @deprecated 큐 기반 메서드 사용 권장: queuePasswordReset
   */
  sendPasswordResetAsync(
    to: string,
    username: string,
    resetToken: string,
  ): void {
    this.queuePasswordReset(to, username, resetToken).catch((error) => {
      this.logger.error('Failed to queue password reset', error);
    });
  }

  /**
   * @deprecated 큐 기반 메서드 사용 권장: queueSecurityAlert
   */
  sendSecurityAlertAsync(
    to: string,
    username: string,
    alertType: string,
    details: { [key: string]: unknown },
  ): void {
    this.queueSecurityAlert(to, username, alertType, details).catch((error) => {
      this.logger.error('Failed to queue security alert', error);
    });
  }

  /**
   * @deprecated 큐 기반 메서드 사용 권장: queue2FAEnabled
   */
  send2FAEnabledAsync(to: string, username: string): void {
    this.queue2FAEnabled(to, username).catch((error) => {
      this.logger.error('Failed to queue 2FA enabled notification', error);
    });
  }

  /**
   * @deprecated 큐 기반 메서드 사용 권장: queueClientCreated
   */
  sendClientCreatedAsync(
    to: string,
    username: string,
    clientName: string,
    clientId: string,
  ): void {
    this.queueClientCreated(to, username, clientName, clientId).catch(
      (error) => {
        this.logger.error('Failed to queue client created notification', error);
      },
    );
  }
}
