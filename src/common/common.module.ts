import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuditLog } from './audit-log.entity';
import { AuditLogService } from './audit-log.service';
import { StatisticsEventService } from './statistics-event.service';

@Module({
  imports: [TypeOrmModule.forFeature([AuditLog])],
  providers: [AuditLogService, StatisticsEventService],
  exports: [AuditLogService, StatisticsEventService],
})
export class CommonModule {}
