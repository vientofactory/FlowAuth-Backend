import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FileUploadService } from './file-upload.service';
import { ImageProcessingService } from './image-processing.service';
import { UploadController } from './upload.controller';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { JwtStrategy } from '../auth/jwt.strategy';
import { UtilsModule } from '../utils/utils.module';
import { AUTH_ENTITIES } from '../database/database.module';

@Module({
  imports: [TypeOrmModule.forFeature(AUTH_ENTITIES), UtilsModule],
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
