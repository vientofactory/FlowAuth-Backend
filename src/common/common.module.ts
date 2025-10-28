import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { StatisticsEventService } from './statistics-event.service';
import { JwtTokenService } from '../oauth2/services/jwt-token.service';

@Module({
  imports: [DatabaseModule],
  providers: [StatisticsEventService, JwtTokenService],
  exports: [StatisticsEventService, JwtTokenService],
})
export class CommonModule {}
