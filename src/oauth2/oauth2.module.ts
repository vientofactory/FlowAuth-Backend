import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { OAuth2Controller } from './oauth2.controller';
import { OAuth2Service } from './oauth2.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { TokenService } from './token.service';
import { ScopeService } from './scope.service';
import { CleanupSchedulerService } from './cleanup-scheduler.service';
import { OAuth2BearerGuard } from './oauth2-bearer.guard';
import { OAuth2ScopeGuard } from './guards/oauth2-scope.guard';
import { OAuth2Strategy } from './guards/oauth2.strategy';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import { Token } from '../token/token.entity';
import { Scope } from '../scope/scope.entity';
import { AppConfigService } from '../config/app-config.service';
import { LoggingModule } from '../logging/logging.module';
import { CacheConfigModule } from '../cache/cache-config.module';
import { JWT_CONSTANTS } from '../constants/auth.constants';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Client, AuthorizationCode, Token, Scope]),
    ScheduleModule.forRoot(),
    LoggingModule,
    CacheConfigModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret:
          configService.get<string>('JWT_SECRET') ||
          JWT_CONSTANTS.SECRET_KEY_FALLBACK,
        signOptions: { expiresIn: JWT_CONSTANTS.EXPIRES_IN },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [OAuth2Controller],
  providers: [
    OAuth2Service,
    AuthorizationCodeService,
    TokenService,
    ScopeService,
    CleanupSchedulerService,
    OAuth2BearerGuard,
    OAuth2ScopeGuard,
    OAuth2Strategy,
    AppConfigService,
  ],
  exports: [OAuth2Service, TokenService, OAuth2BearerGuard, OAuth2ScopeGuard],
})
export class OAuth2Module {}
