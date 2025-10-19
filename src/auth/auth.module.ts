import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TwoFactorService } from './two-factor.service';
import { TwoFactorController } from './two-factor.controller';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard } from './permissions.guard';
import { User } from './user.entity';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';
import { AuthorizationCode } from '../oauth2/authorization-code.entity';
import { LoggingModule } from '../logging/logging.module';
import { UtilsModule } from '../utils/utils.module';
import { JWT_CONSTANTS } from '../constants/auth.constants';
import { UserManagementService } from './services/user-management.service';
import { UserAuthService } from './services/user-auth.service';
import { ClientAuthService } from './services/client-auth.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { ValidationService } from './services/validation.service';
import { UploadModule } from '../upload/upload.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Client, Token, AuthorizationCode]),
    PassportModule,
    LoggingModule,
    UtilsModule,
    UploadModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret:
          configService.get<string>('JWT_SECRET') ||
          JWT_CONSTANTS.SECRET_KEY_FALLBACK,
      }),
      inject: [ConfigService],
    }),
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
