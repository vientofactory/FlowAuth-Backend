import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Client } from '../client/client.entity';
import { User } from '../user/user.entity';
import { Token } from '../token/token.entity';
import { OAuth2Module } from '../oauth2/oauth2.module';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { DashboardStatsService } from './dashboard-stats.service';
import { DashboardAnalyticsService } from './dashboard-analytics.service';
import { CacheManagerService } from './cache-manager.service';
import { LoggingModule } from '../logging/logging.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Client, User, Token]),
    OAuth2Module,
    LoggingModule,
  ],
  controllers: [DashboardController],
  providers: [
    DashboardService,
    DashboardStatsService,
    DashboardAnalyticsService,
    CacheManagerService,
  ],
  exports: [DashboardService, CacheManagerService],
})
export class DashboardModule {}
