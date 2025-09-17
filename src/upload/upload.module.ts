import { Module } from '@nestjs/common';
import { FileUploadService } from './file-upload.service';
import { UploadController } from './upload.controller';

@Module({
  providers: [FileUploadService],
  controllers: [UploadController],
  exports: [FileUploadService],
})
export class UploadModule {}
