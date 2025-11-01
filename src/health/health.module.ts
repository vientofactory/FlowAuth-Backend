import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HealthController } from './health.controller';
import { CommonModule } from '../common/common.module';

@Module({
  imports: [TerminusModule, CommonModule],
  controllers: [HealthController],
})
export class HealthModule {}
