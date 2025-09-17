import {
  Controller,
  Post,
  Get,
  Param,
  Res,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import type { Response } from 'express';
import { FileUploadService } from './file-upload.service';
import type { MulterFile, UploadResponse } from './types';
import { UPLOAD_CONFIG } from './config';
import { UPLOAD_ERRORS } from './types';

// Factory function to create multer options using the service
function createMulterOptions(type: keyof typeof UPLOAD_CONFIG.fileTypes) {
  const service = new FileUploadService();
  return {
    storage: service.createStorage(type),
    fileFilter: service.createFileFilter(type),
    limits: service.getUploadLimits(type),
  };
}

@Controller('uploads')
export class UploadController {
  constructor(private readonly fileUploadService: FileUploadService) {}

  @Post('logo')
  @UseInterceptors(FileInterceptor('logo', createMulterOptions('logo')))
  uploadLogo(@UploadedFile() file: MulterFile): UploadResponse {
    if (!file) {
      throw UPLOAD_ERRORS.NO_FILE_UPLOADED;
    }

    // Validate file using service
    if (!this.fileUploadService.validateFile(file, 'logo')) {
      throw UPLOAD_ERRORS.INVALID_FILE_TYPE;
    }

    // Record successful upload
    this.fileUploadService.recordSuccessfulUpload(file);

    const logoUrl = this.fileUploadService.getFileUrl('logo', file.filename);

    return {
      success: true,
      message: 'Logo uploaded successfully',
      data: {
        filename: file.filename,
        url: logoUrl,
        originalName: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
      },
    };
  }

  @Get('logos/:filename')
  getLogo(@Param('filename') filename: string, @Res() res: Response) {
    // Validate filename to prevent directory traversal
    if (!filename || filename.includes('..') || filename.includes('/')) {
      throw UPLOAD_ERRORS.INVALID_FILE_TYPE;
    }

    const filePath = this.fileUploadService.getFullFilePath('logo', filename);

    // Check if file exists
    if (!this.fileUploadService.fileExists('logo', filename)) {
      throw UPLOAD_ERRORS.FILE_NOT_FOUND;
    }

    // Set appropriate headers for caching
    res.setHeader('Content-Type', 'image/*');
    res.setHeader('Cache-Control', UPLOAD_CONFIG.cache.cacheControl);

    // Send file
    res.sendFile(filePath, (error) => {
      if (error) {
        throw UPLOAD_ERRORS.UPLOAD_FAILED;
      }
    });
  }

  @Get('config/:type')
  getUploadConfig(@Param('type') type: string) {
    const config =
      UPLOAD_CONFIG.fileTypes[type as keyof typeof UPLOAD_CONFIG.fileTypes];

    if (!config) {
      throw new Error(`Upload configuration for type '${type}' not found`);
    }

    return {
      allowedMimes: config.allowedMimes,
      maxSize: config.maxSize,
      maxSizeMB: Math.round((config.maxSize / (1024 * 1024)) * 100) / 100,
      destination: config.destination,
    };
  }
}
