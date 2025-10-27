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
import { DiscoveryController } from './controllers/discovery.controller';
import { JwksController } from './controllers/jwks.controller';
import { OAuth2Service } from './oauth2.service';
import { AuthorizationService } from './services/authorization.service';
import { TokenGrantService } from './services/token-grant.service';
import { TokenIntrospectionService } from './services/token-introspection.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { JwtTokenService } from './services/jwt-token.service';
import { OAuth2TokenService } from './services/oauth2-token.service';
import { TokenRevocationService } from './services/token-revocation.service';
import { IdTokenService } from './services/id-token.service';
import { TokenService } from './token.service';
import { ScopeService } from './scope.service';
import { CleanupSchedulerService } from './cleanup-scheduler.service';
import { OAuth2BearerGuard } from './guards/oauth2-bearer.guard';
import { OAuth2ScopeGuard } from './guards/oauth2-scope.guard';
import { OAuth2Strategy } from './guards/oauth2.strategy';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';
import { AuthorizationCode } from './authorization-code.entity';
import { Token } from './token.entity';
import { Scope } from './scope.entity';
import { OAuth2UserInfoBuilder } from './utils/oauth2-userinfo.util';
import { AppConfigService } from '../config/app-config.service';
import { CacheConfigModule } from '../cache/cache-config.module';
import { CommonModule } from '../common/common.module';
import { JWT_CONSTANTS } from '../constants/auth.constants';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Client, AuthorizationCode, Token, Scope]),
    ScheduleModule.forRoot(),
    CacheConfigModule,
    CommonModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret:
          configService.get<string>('JWT_SECRET') ??
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
    DiscoveryController,
    JwksController,
  ],
  providers: [
    OAuth2Service,
    AuthorizationService,
    TokenGrantService,
    TokenIntrospectionService,
    AuthorizationCodeService,
    TokenService,
    JwtTokenService,
    OAuth2TokenService,
    TokenRevocationService,
    IdTokenService,
    ScopeService,
    CleanupSchedulerService,
    OAuth2BearerGuard,
    OAuth2ScopeGuard,
    OAuth2Strategy,
    AppConfigService,
    OAuth2UserInfoBuilder,
  ],
  exports: [
    OAuth2Service,
    TokenService,
    TokenIntrospectionService,
    TokenRevocationService,
    OAuth2BearerGuard,
    OAuth2ScopeGuard,
  ],
})
export class OAuth2Module {}
