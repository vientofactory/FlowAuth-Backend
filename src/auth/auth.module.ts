import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TwoFactorService } from './two-factor.service';
import { TwoFactorController } from './two-factor.controller';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard } from './permissions.guard';
import { UtilsModule } from '../utils/utils.module';
import { UserManagementService } from './services/user-management.service';
import { UserAuthService } from './services/user-auth.service';
import { ClientAuthService } from './services/client-auth.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { ValidationService } from './services/validation.service';
import { UploadModule } from '../upload/upload.module';
import { CommonModule } from '../common/common.module';
import { AuditLogService } from '../common/audit-log.service';
import { CacheConfigModule } from '../cache/cache-config.module';
import { AUTH_ENTITIES } from '../database/database.module';
import { EmailModule } from '../email/email.module';

@Module({
  imports: [
    TypeOrmModule.forFeature(AUTH_ENTITIES),
    UtilsModule,
    UploadModule,
    CommonModule,
    CacheConfigModule,
    EmailModule,
  ],
  providers: [
    AuthService,
    TwoFactorService,
    JwtStrategy,
    JwtAuthGuard,
    PermissionsGuard,
    UserManagementService,
    UserAuthService,
    ClientAuthService,
    TwoFactorAuthService,
    ValidationService,
    AuditLogService,
  ],
  controllers: [AuthController, TwoFactorController],
  exports: [
    JwtAuthGuard,
    UserManagementService,
    UserAuthService,
    ClientAuthService,
  ],
})
export class AuthModule {}
