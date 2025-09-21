import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { Token } from '../token/token.entity';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import { Scope } from '../scope/scope.entity';
import { SeedService } from './seed.service';

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
        entities: [User, Client, Token, AuthorizationCode, Scope],
        synchronize: configService.get<string>('NODE_ENV') !== 'production',
        logging: configService.get<string>('NODE_ENV') === 'development',
        cache: configService.get('REDIS_HOST')
          ? {
              type: 'redis',
              options: {
                host: configService.get<string>('REDIS_HOST', 'localhost'),
                port: configService.get<number>('REDIS_PORT', 6379),
                password: configService.get<string>('REDIS_PASSWORD'),
                db: configService.get<string>('REDIS_DB'),
              },
              duration: configService.get<number>('CACHE_TTL', 300000),
            }
          : false,
      }),
      inject: [ConfigService],
    }),
    TypeOrmModule.forFeature([Scope, Client, User]),
  ],
  providers: [SeedService],
  exports: [SeedService],
})
export class DatabaseModule {}
