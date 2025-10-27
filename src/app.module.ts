import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule } from '@nestjs/throttler';
import { CacheConfigModule } from './cache/cache-config.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { OAuth2Module } from './oauth2/oauth2.module';
import { DatabaseModule } from './database/database.module';
import { AppConfigService } from './config/app-config.service';
import { UploadModule } from './upload/upload.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { ProfileModule } from './profile/profile.module';
import { CommonModule } from './common/common.module';
import { HealthModule } from './health/health.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    CacheConfigModule,
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60000, // 1분
          limit: 10, // 1분에 10개 요청
        },
      ],
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    DatabaseModule,
    AuthModule,
    OAuth2Module,
    UploadModule,
    DashboardModule,
    ProfileModule,
    CommonModule,
    HealthModule,
  ],
  controllers: [AppController],
  providers: [AppService, AppConfigService],
})
export class AppModule {}
