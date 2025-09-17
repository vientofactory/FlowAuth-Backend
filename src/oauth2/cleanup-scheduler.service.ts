import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TokenService } from './token.service';
import { AuthorizationCodeService } from './authorization-code.service';

@Injectable()
export class CleanupSchedulerService {
  private readonly logger = new Logger(CleanupSchedulerService.name);

  constructor(
    private readonly tokenService: TokenService,
    private readonly authorizationCodeService: AuthorizationCodeService,
  ) {}

  @Cron(CronExpression.EVERY_10_MINUTES)
  async handleCleanupExpiredTokens() {
    try {
      await this.tokenService.cleanupExpiredTokens();
      await this.authorizationCodeService.cleanupExpiredCodes();
    } catch (error) {
      this.logger.error('Failed to cleanup expired tokens and codes', error);
    }
  }
}
