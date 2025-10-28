import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
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
import { AppConfigService } from '../config/app-config.service';
import { CacheConfigModule } from '../cache/cache-config.module';
import { CommonModule } from '../common/common.module';
import { AuditLogService } from '../common/audit-log.service';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';
import { AuthorizationCode } from './authorization-code.entity';
import { Token } from './token.entity';
import { Scope } from './scope.entity';
import { AuditLog } from '../common/audit-log.entity';
import { OAuth2UserInfoBuilder } from './utils/oauth2-userinfo.util';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      Client,
      AuthorizationCode,
      Token,
      Scope,
      AuditLog,
    ]),
    ScheduleModule.forRoot(),
    CacheConfigModule,
    CommonModule,
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
    AuditLogService,
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
