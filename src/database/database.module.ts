import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SeedService } from './seed.service';
import { DatabaseInitializationService } from './database-initialization.service';
// Import all entities to register them globally
import { User } from '../auth/user.entity';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';
import { AuthorizationCode } from '../oauth2/authorization-code.entity';
import { Scope } from '../oauth2/scope.entity';
import { AuditLog } from '../common/audit-log.entity';
import {
  TokenStatistics,
  ScopeStatistics,
  ClientStatistics,
} from '../dashboard/statistics.entity';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'mysql',
        host: configService.get<string>('DB_HOST', 'localhost'),
        port: configService.get<number>('DB_PORT', 3306),
        username: configService.get<string>('DB_USERNAME', 'root'),
        password: configService.get<string>('DB_PASSWORD', ''),
        database: configService.get<string>('DB_NAME', 'flowauth'),
        entities: [
          User,
          Client,
          Token,
          AuthorizationCode,
          Scope,
          AuditLog,
          TokenStatistics,
          ScopeStatistics,
          ClientStatistics,
        ],
        synchronize: false,
        logging: configService.get<string>('NODE_ENV') === 'development',
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [SeedService, DatabaseInitializationService],
  exports: [SeedService, DatabaseInitializationService],
})
export class DatabaseModule {}
