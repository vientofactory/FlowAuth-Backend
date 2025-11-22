import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { TokenService } from './token.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { AuditLogService } from '../common/audit-log.service';

@Injectable()
export class CleanupSchedulerService {
  private readonly logger = new Logger(CleanupSchedulerService.name);

  constructor(
    private readonly tokenService: TokenService,
    private readonly authorizationCodeService: AuthorizationCodeService,
    private readonly auditLogService: AuditLogService,
  ) {}

  @Cron(CronExpression.EVERY_10_MINUTES)
  async handleCleanupExpiredTokens() {
    try {
      const deletedTokens = await this.tokenService.cleanupExpiredTokens();
      const deletedCodes =
        await this.authorizationCodeService.cleanupExpiredCodes();

      if (deletedTokens > 0 || deletedCodes > 0) {
        this.logger.log(
          `Cleanup completed: ${deletedTokens} expired tokens and ${deletedCodes} expired authorization codes removed`,
        );
      }
    } catch (error) {
      this.logger.error('Failed to cleanup expired tokens and codes', error);
    }
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleCleanupOldAuditLogs() {
    try {
      await this.auditLogService.cleanupOldLogs(30); // 30 days
    } catch (error) {
      this.logger.error('Failed to cleanup old audit logs', error);
    }
  }
}
