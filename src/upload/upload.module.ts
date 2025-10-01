import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { FileUploadService } from './file-upload.service';
import { ImageProcessingService } from './image-processing.service';
import { UploadController } from './upload.controller';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { JwtStrategy } from '../auth/jwt.strategy';
import { User } from '../auth/user.entity';
import { Token } from '../oauth2/token.entity';
import { JWT_CONSTANTS } from '../constants/auth.constants';
import { UtilsModule } from '../utils/utils.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Token]),
    PassportModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret:
          configService.get<string>('JWT_SECRET') ||
          JWT_CONSTANTS.SECRET_KEY_FALLBACK,
        signOptions: { expiresIn: JWT_CONSTANTS.EXPIRES_IN },
      }),
      inject: [ConfigService],
    }),
    UtilsModule,
  ],
  providers: [
    FileUploadService,
    ImageProcessingService,
    JwtAuthGuard,
    JwtStrategy,
  ],
  controllers: [UploadController],
  exports: [FileUploadService],
})
export class UploadModule {}
