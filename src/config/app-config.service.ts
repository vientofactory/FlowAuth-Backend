import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JWT_TOKEN_EXPIRY } from '@flowauth/shared';

@Injectable()
export class AppConfigService {
  // OAuth2 Token Configuration
  readonly accessTokenExpiryHours: number;
  readonly refreshTokenExpiryDays: number;

  // OAuth2 Authorization Code Configuration
  readonly codeExpiryMinutes: number;
  readonly codeLength: number;

  // Database Configuration
  readonly dbHost: string;
  readonly dbPort: number;
  readonly dbUsername: string;
  readonly dbPassword: string;
  readonly dbName: string;
  readonly dbConnectionLimit: number;
  readonly dbAcquireTimeout: number;
  readonly dbTimeout: number;

  // Cache Configuration
  readonly cacheTtl: number; // milliseconds

  // JWT Configuration
  readonly jwtSecret: string;
  readonly jwtExpiry: string;

  // reCAPTCHA Configuration
  readonly recaptchaSecretKey: string;
  readonly recaptchaScoreThreshold: number;

  // Cleanup Configuration
  readonly cleanupCronExpression: string;

  constructor(private configService: ConfigService) {
    // OAuth2 Token Configuration
    this.accessTokenExpiryHours = parseInt(
      this.configService.get<string>('OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS') ??
        JWT_TOKEN_EXPIRY.OAUTH2_HOURS.toString(),
      10,
    );
    this.refreshTokenExpiryDays = parseInt(
      this.configService.get<string>('OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS') ??
        '30',
      10,
    );

    // OAuth2 Authorization Code Configuration
    this.codeExpiryMinutes = parseInt(
      this.configService.get<string>('OAUTH2_CODE_EXPIRY_MINUTES') ?? '10',
      10,
    );
    this.codeLength = parseInt(
      this.configService.get<string>('OAUTH2_CODE_LENGTH') ?? '32',
      10,
    );

    // Database Configuration
    this.dbHost = this.configService.get<string>('DB_HOST') ?? 'localhost';
    this.dbPort = parseInt(
      this.configService.get<string>('DB_PORT') ?? '3306',
      10,
    );
    this.dbUsername = this.configService.get<string>('DB_USERNAME') ?? 'root';
    this.dbPassword = this.configService.get<string>('DB_PASSWORD') ?? '';
    this.dbName = this.configService.get<string>('DB_NAME') ?? 'flowauth';
    this.dbConnectionLimit = parseInt(
      this.configService.get<string>('DB_CONNECTION_LIMIT') ?? '10',
      10,
    );
    this.dbAcquireTimeout = parseInt(
      this.configService.get<string>('DB_ACQUIRE_TIMEOUT') ?? '60000',
      10,
    );
    this.dbTimeout = parseInt(
      this.configService.get<string>('DB_TIMEOUT') ?? '60000',
      10,
    );

    // Cache Configuration
    this.cacheTtl = parseInt(
      this.configService.get<string>('CACHE_TTL') ?? '300000', // 5 minutes
      10,
    );

    // JWT Configuration
    this.jwtSecret =
      this.configService.get<string>('JWT_SECRET') ?? 'your-secret-key';
    this.jwtExpiry = this.configService.get<string>('JWT_EXPIRY') ?? '1h';

    // reCAPTCHA Configuration
    this.recaptchaSecretKey =
      this.configService.get<string>('RECAPTCHA_SECRET_KEY') ?? '';
    this.recaptchaScoreThreshold = parseFloat(
      this.configService.get<string>('RECAPTCHA_SCORE_THRESHOLD') ?? '0.5',
    );

    // Cleanup Configuration
    this.cleanupCronExpression =
      this.configService.get<string>('CLEANUP_CRON_EXPRESSION') ?? '0 0 * * *';
  }

  // Validation methods
  validateConfiguration(): void {
    const errors: string[] = [];

    if (!this.jwtSecret || this.jwtSecret === 'your-secret-key') {
      errors.push('JWT_SECRET must be set to a secure value');
    }

    if (this.accessTokenExpiryHours <= 0) {
      errors.push('OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS must be greater than 0');
    }

    if (this.refreshTokenExpiryDays <= 0) {
      errors.push('OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS must be greater than 0');
    }

    if (this.codeExpiryMinutes <= 0) {
      errors.push('OAUTH2_CODE_EXPIRY_MINUTES must be greater than 0');
    }

    if (this.codeLength < 16) {
      errors.push('OAUTH2_CODE_LENGTH must be at least 16');
    }

    if (errors.length > 0) {
      throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
    }
  }
}
