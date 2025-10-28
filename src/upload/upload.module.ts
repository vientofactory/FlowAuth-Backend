import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FileUploadService } from './file-upload.service';
import { ImageProcessingService } from './image-processing.service';
import { UploadController } from './upload.controller';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { JwtStrategy } from '../auth/jwt.strategy';
import { User } from '../auth/user.entity';
import { Token } from '../oauth2/token.entity';
import { UtilsModule } from '../utils/utils.module';

@Module({
  imports: [TypeOrmModule.forFeature([User, Token]), UtilsModule],
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
