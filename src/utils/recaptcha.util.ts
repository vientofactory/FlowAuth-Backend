import { Injectable, Logger } from '@nestjs/common';
import { AppConfigService } from '../config/app-config.service';

interface RecaptchaResponse {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  'error-codes'?: string[];
  score?: number;
  action?: string;
}

@Injectable()
export class RecaptchaService {
  private readonly logger = new Logger(RecaptchaService.name);

  constructor(private appConfigService: AppConfigService) {}

  async verifyToken(token: string, expectedAction?: string): Promise<boolean> {
    const secretKey = this.appConfigService.recaptchaSecretKey;

    if (!secretKey) {
      this.logger.warn(
        'RECAPTCHA_SECRET_KEY is not configured, skipping verification',
      );
      return true; // 개발 환경에서는 검증을 스킵
    }

    if (!token) {
      this.logger.warn('reCAPTCHA token is missing');
      return false;
    }

    try {
      const response = await fetch(
        'https://www.google.com/recaptcha/api/siteverify',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            secret: secretKey,
            response: token,
          }),
        },
      );

      if (!response.ok) {
        this.logger.error(
          `reCAPTCHA API request failed with status: ${response.status}`,
        );
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = (await response.json()) as RecaptchaResponse;

      // v2 호환성을 위한 기본 검증
      if (!data.success) {
        const errorCodes = data['error-codes']?.join(', ') || 'Unknown error';
        this.logger.error(`reCAPTCHA verification failed: ${errorCodes}`);

        // 키 타입 오류인 경우 더 자세한 로깅
        if (
          errorCodes.includes('invalid-input-secret') ||
          errorCodes.includes('invalid-keys') ||
          errorCodes.includes('bad-request')
        ) {
          this.logger.error(`reCAPTCHA key configuration issue. Please check:`);
          this.logger.error(`- Secret key format and validity`);
          this.logger.error(`- Site key matches the secret key`);
          this.logger.error(`- Keys are for reCAPTCHA v3`);
        }

        return false;
      }

      // v3 점수 기반 검증
      if (data.score !== undefined) {
        this.logger.debug(
          `reCAPTCHA score: ${data.score}, action: ${data.action}`,
        );

        // 점수 임계값 검증
        if (data.score < this.appConfigService.recaptchaScoreThreshold) {
          this.logger.warn(
            `reCAPTCHA score too low: ${data.score} < ${this.appConfigService.recaptchaScoreThreshold}`,
          );
          return false;
        }

        // 액션 검증 (선택적)
        if (expectedAction && data.action !== expectedAction) {
          this.logger.warn(
            `reCAPTCHA action mismatch: expected ${expectedAction}, got ${data.action}`,
          );
          return false;
        }
      }

      this.logger.debug('reCAPTCHA verification successful');
      return true;
    } catch (error) {
      this.logger.error('reCAPTCHA verification error:', error);
      return false;
    }
  }
  /**
   * reCAPTCHA 점수만 반환 (추가 검증 로직용)
   */
  async getScore(token: string): Promise<number | null> {
    const secretKey = this.appConfigService.recaptchaSecretKey;

    if (!secretKey || !token) {
      return null;
    }

    try {
      const response = await fetch(
        'https://www.google.com/recaptcha/api/siteverify',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            secret: secretKey,
            response: token,
          }),
        },
      );

      if (!response.ok) {
        return null;
      }

      const data = (await response.json()) as RecaptchaResponse;
      return data.success && data.score !== undefined ? data.score : null;
    } catch (error) {
      this.logger.error('Failed to get reCAPTCHA score:', error);
      return null;
    }
  }
}
