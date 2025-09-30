import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { AuthorizationController } from './controllers/authorization.controller';
import { TokenController } from './controllers/token.controller';
import { UserInfoController } from './controllers/userinfo.controller';
import { ConsentController } from './controllers/consent.controller';
import { ScopeController } from './controllers/scope.controller';
import { OAuth2Service } from './oauth2.service';
import { AuthorizationService } from './services/authorization.service';
import { TokenGrantService } from './services/token-grant.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { TokenService } from './token.service';
import { ScopeService } from './scope.service';
import { CleanupSchedulerService } from './cleanup-scheduler.service';
import { OAuth2BearerGuard } from './guards/oauth2-bearer.guard';
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
  controllers: [
    AuthorizationController,
    TokenController,
    UserInfoController,
    ConsentController,
    ScopeController,
  ],
  providers: [
    OAuth2Service,
    AuthorizationService,
    TokenGrantService,
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
