import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import { readFileSync } from 'fs';
import { join } from 'path';

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

  constructor(private configService: ConfigService) {
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
    this.logger.log('SMTP transporter initialized');
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
   * 템플릿 경로를 동적으로 생성 (개발/프로덕션 환경 대응)
   */
  private getTemplatePath(templateName: string): string | null {
    // 보안 검증: 허용된 템플릿만 사용
    type AllowedTemplate = (typeof this.allowedTemplates)[number];
    if (!this.allowedTemplates.includes(templateName as AllowedTemplate)) {
      return null;
    }

    // 개발 환경에서는 src 폴더, 프로덕션에서는 dist 폴더 사용
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

      this.logger.log(
        `Email sent successfully to ${to} using template ${templateName}`,
      );
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
      this.logger.log('SMTP connection test successful');
      return true;
    } catch (error) {
      this.logger.error(
        'SMTP connection test failed',
        error instanceof Error ? error.stack : undefined,
      );
      return false;
    }
  }

  // === 비동기 이메일 전송 메서드들 (즉시 응답) ===

  /**
   * 환영 이메일을 백그라운드에서 전송 (즉시 응답)
   */
  sendWelcomeEmailAsync(to: string, username: string): void {
    setImmediate(() => {
      this.sendWelcomeEmail(to, username).catch((error) => {
        this.logger.error('Background welcome email failed', error);
      });
    });
  }

  /**
   * 이메일 인증을 백그라운드에서 전송 (즉시 응답)
   */
  sendEmailVerificationAsync(
    to: string,
    username: string,
    verificationToken: string,
  ): void {
    setImmediate(() => {
      this.sendEmailVerification(to, username, verificationToken).catch(
        (error) => {
          this.logger.error('Background email verification failed', error);
          // 중요한 이메일이므로 재시도
          setTimeout(() => {
            this.sendEmailVerification(to, username, verificationToken).catch(
              (retryError) => {
                this.logger.error(
                  'Email verification retry failed',
                  retryError,
                );
              },
            );
          }, 5000);
        },
      );
    });
  }

  /**
   * 비밀번호 재설정을 백그라운드에서 전송 (즉시 응답)
   */
  sendPasswordResetAsync(
    to: string,
    username: string,
    resetToken: string,
  ): void {
    setImmediate(() => {
      this.sendPasswordReset(to, username, resetToken).catch((error) => {
        this.logger.error('Background password reset failed', error);
        // 중요한 이메일이므로 재시도
        setTimeout(() => {
          this.sendPasswordReset(to, username, resetToken).catch(
            (retryError) => {
              this.logger.error('Password reset retry failed', retryError);
            },
          );
        }, 5000);
      });
    });
  }

  /**
   * 보안 알림을 백그라운드에서 전송 (즉시 응답)
   */
  sendSecurityAlertAsync(
    to: string,
    username: string,
    alertType: string,
    details: { [key: string]: unknown },
  ): void {
    setImmediate(() => {
      this.sendSecurityAlert(to, username, alertType, details).catch(
        (error) => {
          this.logger.error('Background security alert failed', error);
        },
      );
    });
  }

  /**
   * 2FA 활성화 알림을 백그라운드에서 전송 (즉시 응답)
   */
  send2FAEnabledAsync(to: string, username: string): void {
    setImmediate(() => {
      this.send2FAEnabled(to, username).catch((error) => {
        this.logger.error('Background 2FA notification failed', error);
      });
    });
  }

  /**
   * 클라이언트 생성 알림을 백그라운드에서 전송 (즉시 응답)
   */
  sendClientCreatedAsync(
    to: string,
    username: string,
    clientName: string,
    clientId: string,
  ): void {
    setImmediate(() => {
      this.sendClientCreated(to, username, clientName, clientId).catch(
        (error) => {
          this.logger.error(
            'Background client created notification failed',
            error,
          );
        },
      );
    });
  }
}
