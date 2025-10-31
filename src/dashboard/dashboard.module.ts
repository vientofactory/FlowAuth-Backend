import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { DashboardStatsService } from './dashboard-stats.service';
import { DashboardAnalyticsService } from './dashboard-analytics.service';
import { TokenAnalyticsService } from './token-analytics.service';
import { SecurityMetricsService } from './security-metrics.service';
import { StatisticsRecordingService } from './statistics-recording.service';
import { AuditLogService } from '../common/audit-log.service';
import { CommonModule } from '../common/common.module';
import { CacheConfigModule } from '../cache/cache-config.module';
import { AUTH_ENTITIES, DASHBOARD_ENTITIES } from '../database/database.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([...AUTH_ENTITIES, ...DASHBOARD_ENTITIES]),
    CommonModule,
    CacheConfigModule,
  ],
  controllers: [DashboardController],
  providers: [
    DashboardService,
    DashboardStatsService,
    DashboardAnalyticsService,
    TokenAnalyticsService,
    SecurityMetricsService,
    StatisticsRecordingService,
    AuditLogService,
  ],
  exports: [DashboardService, StatisticsRecordingService],
})
export class DashboardModule {}
