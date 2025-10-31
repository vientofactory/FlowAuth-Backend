import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { CacheConfigModule } from '../cache/cache-config.module';
import { StatisticsEventService } from './statistics-event.service';
import { JwtTokenService } from '../oauth2/services/jwt-token.service';

@Module({
  imports: [DatabaseModule, CacheConfigModule],
  providers: [StatisticsEventService, JwtTokenService],
  exports: [StatisticsEventService, JwtTokenService],
})
export class CommonModule {}
