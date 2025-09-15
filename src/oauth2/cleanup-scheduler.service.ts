import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TokenService } from './token.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { AppConfigService } from '../config/app-config.service';

@Injectable()
export class CleanupSchedulerService {
  private readonly logger = new Logger(CleanupSchedulerService.name);

  constructor(
    private readonly tokenService: TokenService,
    private readonly authorizationCodeService: AuthorizationCodeService,
    private readonly appConfig: AppConfigService,
  ) {}

  @Cron(CronExpression.EVERY_10_MINUTES)
  async handleCleanupExpiredTokens() {
    try {
      const deletedTokens = await this.tokenService.cleanupExpiredTokens();
      const deletedCodes =
        await this.authorizationCodeService.cleanupExpiredCodes();

      this.logger.log(
        `Cleanup completed: ${deletedTokens} expired tokens and ${deletedCodes} expired authorization codes removed`,
      );
    } catch (error) {
      this.logger.error('Failed to cleanup expired tokens and codes', error);
    }
  }
}
