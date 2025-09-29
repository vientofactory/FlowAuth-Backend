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
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { Token } from '../token/token.entity';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import { LoggingModule } from '../logging/logging.module';
import { UtilsModule } from '../utils/utils.module';
import { JWT_CONSTANTS } from '../constants/auth.constants';
import { UserManagementService } from './services/user-management.service';
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
  ],
  controllers: [AuthController, TwoFactorController],
  exports: [JwtAuthGuard, UserManagementService],
})
export class AuthModule {}
