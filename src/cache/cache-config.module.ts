import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { CacheManagerService } from './cache-manager.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AUTH_ENTITIES } from '../database/database.module';

@Module({
  imports: [TypeOrmModule.forFeature(AUTH_ENTITIES)],
  providers: [
    CacheManagerService,
    {
      provide: 'REDIS_CLIENT',
      useFactory: (configService: ConfigService) => {
        return new Redis({
          host: configService.get<string>('REDIS_HOST') ?? 'localhost',
          port: parseInt(configService.get<string>('REDIS_PORT') ?? '6379'),
          password: configService.get<string>('REDIS_PASSWORD') ?? undefined,
        });
      },
      inject: [ConfigService],
    },
  ],
  exports: [CacheManagerService, 'REDIS_CLIENT'],
})
export class CacheConfigModule {}
