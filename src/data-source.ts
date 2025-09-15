import { DataSource } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { config } from 'dotenv';
import { AppConfigService } from './config/app-config.service';

config();

const configService = new ConfigService();
const appConfig = new AppConfigService(configService);

// Validate configuration on startup
appConfig.validateConfiguration();

export default new DataSource({
  type: 'mysql',
  host: appConfig.dbHost,
  port: appConfig.dbPort,
  username: appConfig.dbUsername,
  password: appConfig.dbPassword,
  database: appConfig.dbName,
  entities: ['src/**/*.entity{.ts,.js}'],
  migrations: ['src/migrations/*{.ts,.js}'],
  synchronize: false, // 프로덕션에서는 false
  logging: configService.get<string>('NODE_ENV') === 'development',
  extra: {
    connectionLimit: appConfig.dbConnectionLimit,
    acquireTimeout: appConfig.dbAcquireTimeout,
    timeout: appConfig.dbTimeout,
  },
  cache: {
    type: 'redis',
    options: {
      host: appConfig.redisHost,
      port: appConfig.redisPort,
      password: appConfig.redisPassword,
      db: appConfig.redisDb,
    },
    duration: appConfig.cacheTtl,
  },
});
