import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Client } from '../oauth2/client.entity';
import { User } from '../auth/user.entity';
import { Token } from '../oauth2/token.entity';
import { AuditLog } from '../common/audit-log.entity';
import {
  TokenStatistics,
  ScopeStatistics,
  ClientStatistics,
} from './statistics.entity';
import { OAuth2Module } from '../oauth2/oauth2.module';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { DashboardStatsService } from './dashboard-stats.service';
import { DashboardAnalyticsService } from './dashboard-analytics.service';
import { TokenAnalyticsService } from './token-analytics.service';
import { SecurityMetricsService } from './security-metrics.service';
import { CacheManagerService } from './cache-manager.service';
import { StatisticsRecordingService } from './statistics-recording.service';
import { CommonModule } from '../common/common.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Client,
      User,
      Token,
      AuditLog,
      TokenStatistics,
      ScopeStatistics,
      ClientStatistics,
    ]),
    OAuth2Module,
    CommonModule,
  ],
  controllers: [DashboardController],
  providers: [
    DashboardService,
    DashboardStatsService,
    DashboardAnalyticsService,
    TokenAnalyticsService,
    SecurityMetricsService,
    CacheManagerService,
    StatisticsRecordingService,
  ],
  exports: [DashboardService, CacheManagerService, StatisticsRecordingService],
})
export class DashboardModule {}
