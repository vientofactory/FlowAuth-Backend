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
import { FileUploadService } from '../upload/file-upload.service';
import { RecaptchaService } from '../utils/recaptcha.util';
import { AppConfigService } from '../config/app-config.service';
import { LoggingModule } from '../logging/logging.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Client, Token, AuthorizationCode]),
    PassportModule,
    LoggingModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET') || 'your-secret-key',
        signOptions: { expiresIn: '1h' },
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
    FileUploadService,
    RecaptchaService,
    AppConfigService,
  ],
  controllers: [AuthController, TwoFactorController],
  exports: [JwtAuthGuard, FileUploadService],
})
export class AuthModule {}
