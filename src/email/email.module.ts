import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BullModule } from '@nestjs/bull';
import { EmailService } from './email.service';
import { EmailController } from './email.controller';
import { EmailProcessor } from './email.processor';
import { EmailQueueService } from './email-queue.service';
import { EmailQueueController } from './email-queue.controller';

@Module({
  imports: [
    ConfigModule,
    // Bull Queue 설정
    BullModule.registerQueueAsync({
      name: 'email',
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        redis: {
          host: configService.get<string>('REDIS_HOST', 'localhost'),
          port: configService.get<number>('REDIS_PORT', 6379),
          password: configService.get<string>('REDIS_PASSWORD'),
          db: configService.get<number>('REDIS_DB', 0),
        },
        defaultJobOptions: {
          removeOnComplete: 100,
          removeOnFail: 50,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000,
          },
        },
        settings: {
          stalledInterval: 30 * 1000, // 30초
          maxStalledCount: 1,
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [EmailController, EmailQueueController],
  providers: [EmailService, EmailProcessor, EmailQueueService],
  exports: [EmailService, EmailQueueService],
})
export class EmailModule {}
