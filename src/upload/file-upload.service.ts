import { Injectable, Logger } from '@nestjs/common';
import { existsSync, unlinkSync } from 'fs';
import { memoryStorage } from 'multer';
import {
  safePath,
  validateFilename,
  sanitizeFilename,
} from '../utils/path-security.util';
import type { Request } from 'express';
import {
  MulterFile,
  UploadedFile,
  MulterFileFilterCallback,
  FileUploadError,
} from './types';
import { UPLOAD_CONFIG, getUploadPath, getFileUrl } from './config';
import { fileUploadValidator } from './validators';
import { ImageProcessingService } from './image-processing.service';

@Injectable()
export class FileUploadService {
  private readonly logger = new Logger(FileUploadService.name);

  constructor(
    private readonly imageProcessingService: ImageProcessingService,
  ) {}

  /**
   * Create multer storage configuration for a specific file type
   */
  createStorage() {
    // Use memory storage for image processing with Sharp
    return memoryStorage();
  }

  /**
   * Create multer file filter for a specific file type
   */
  createFileFilter(type: keyof typeof UPLOAD_CONFIG.fileTypes) {
    return (req: Request, file: MulterFile, cb: MulterFileFilterCallback) => {
      try {
        // Use centralized validation but skip size validation in fileFilter
        // (size validation will be done after file is fully uploaded)
        const validationResult = fileUploadValidator.validateFile(file, type, {
          skipSizeValidation: true,
        });

        if (!validationResult.isValid) {
          const error = new FileUploadError(
            validationResult.errors.join('; '),
            'INVALID_FILE',
          );
          this.logger.warn(
            `File validation failed: ${file.originalname} - ${validationResult.errors.join('; ')}`,
          );
          cb(error, false);
          return;
        }

        // Log warnings if any
        if (validationResult.warnings.length > 0) {
          this.logger.warn(
            `File validation warnings: ${file.originalname} - ${validationResult.warnings.join('; ')}`,
          );
        }

        cb(null, true);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        const stack = error instanceof Error ? error.stack : undefined;
        this.logger.error(`File filter error: ${message}`, stack);
        cb(error instanceof Error ? error : new Error(String(error)), false);
      }
    };
  }

  /**
   * Validate uploaded file (legacy method for backward compatibility)
   * @deprecated Use fileUploadValidator.validateFile() directly for more detailed validation
   */
  validateFile(
    file: MulterFile,
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
  ): boolean {
    const result = fileUploadValidator.validateFile(file, type);
    return result.isValid;
  }

  /**
   * Get file URL for a specific type and filename
   */
  getFileUrl(
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    filename: string,
  ): string {
    // Use type-safe helper function (returns relative path)
    const fullUrl = getFileUrl(type, filename);
    // Remove backend host part and return only relative path
    return fullUrl.replace(/^https?:\/\/[^/]+/, '');
  }

  /**
   * Get full file path for a specific type and filename
   */
  getFullFilePath(
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    filename: string,
  ): string {
    // Validate and sanitize filename
    if (!validateFilename(filename)) {
      throw new Error('Invalid filename detected');
    }

    const sanitizedFilename = sanitizeFilename(filename);
    const destination = getUploadPath(type);

    // Use safePath to prevent directory traversal
    return safePath(sanitizedFilename, destination);
  }

  /**
   * Check if file exists
   */
  fileExists(
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    filename: string,
  ): boolean {
    const filePath = this.getFullFilePath(type, filename);
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return existsSync(filePath);
  }

  /**
   * Get file info for response
   */
  getFileInfo(
    file: MulterFile,
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
  ): UploadedFile {
    return {
      filename: file.filename,
      originalname: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      path: file.path,
      url: this.getFileUrl(type, file.filename),
    };
  }

  /**
   * Delete a file from the filesystem
   * @param logoUri - The URI of the file to delete (e.g., '/uploads/logos/filename.png')
   * @returns Promise<boolean> - true if deleted successfully, false otherwise
   */
  deleteFile(logoUri: string): boolean {
    try {
      this.logger.log(`Attempting to delete file: ${logoUri}`);

      if (!logoUri || typeof logoUri !== 'string') {
        this.logger.warn('Invalid logoUri provided for deletion');
        return false;
      }

      // Remove leading slash and extract relative path
      const relativePath = logoUri.startsWith('/') ? logoUri.slice(1) : logoUri;
      this.logger.log(`Relative path extracted: ${relativePath}`);

      // Check if it's an upload path
      if (!relativePath.startsWith('uploads/')) {
        this.logger.warn(
          `File path does not start with 'uploads/': ${relativePath}`,
        );
        return false;
      }

      // Build absolute file path safely
      try {
        const filePath = safePath(relativePath, process.cwd());
        this.logger.log(`Absolute file path resolved: ${filePath}`);

        // Check if file exists
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        if (!existsSync(filePath)) {
          this.logger.warn(`File does not exist: ${filePath}`);
          return false;
        }

        // Delete the file
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        unlinkSync(filePath);
        this.logger.log(`File successfully deleted: ${filePath}`);
        return true;
      } catch (error) {
        this.logger.error(
          `Failed to delete file: ${logoUri}`,
          error instanceof Error ? error.stack : String(error),
        );
        return false;
      }
    } catch (error) {
      this.logger.error(
        `Unexpected error during file deletion: ${logoUri}`,
        error instanceof Error ? error.stack : String(error),
      );
      return false;
    }
  }

  /**
   * Process and save a logo image
   * @param file - The uploaded logo file
   * @returns Promise<string> - URL of the processed logo
   */
  async processLogoImage(file: MulterFile): Promise<string> {
    return this.imageProcessingService.processAndSaveImage('logo', file);
  }

  /**
   * Process and save an avatar image
   * @param userId - The user ID
   * @param file - The uploaded avatar file
   * @returns Promise<string> - URL of the processed avatar
   */
  async processAvatarImage(userId: number, file: MulterFile): Promise<string> {
    return this.imageProcessingService.processAndSaveImage(
      'avatar',
      file,
      userId,
    );
  }
}
