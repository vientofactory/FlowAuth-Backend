import { Module } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';
import { winstonConfig } from './winston.config';
import { StructuredLogger } from './structured-logger.service';

@Module({
  imports: [WinstonModule.forRoot(winstonConfig)],
  providers: [StructuredLogger],
  exports: [StructuredLogger],
})
export class LoggingModule {}
