import { Injectable, Logger } from '@nestjs/common';
import { extname, join } from 'path';
import { existsSync, mkdirSync, unlinkSync } from 'fs';
import { diskStorage } from 'multer';
import { v4 as uuidv4 } from 'uuid';
import type { Request } from 'express';
import {
  MulterFile,
  UploadedFile,
  UploadLimits,
  MulterDestinationCallback,
  MulterFilenameCallback,
  MulterFileFilterCallback,
  FileUploadError,
} from './types';
import { UPLOAD_CONFIG, getUploadPath } from './config';
import { fileUploadValidator } from './validators';

@Injectable()
export class FileUploadService {
  private readonly logger = new Logger(FileUploadService.name);

  constructor() {
    this.ensureDirectoriesExist();
  }

  private ensureDirectoriesExist(): void {
    if (!existsSync(UPLOAD_CONFIG.baseUploadPath)) {
      mkdirSync(UPLOAD_CONFIG.baseUploadPath, { recursive: true });
      this.logger.log(
        `Created base upload directory: ${UPLOAD_CONFIG.baseUploadPath}`,
      );
    }

    // Create directories for each file type
    Object.keys(UPLOAD_CONFIG.fileTypes).forEach((type) => {
      const path = getUploadPath(type as keyof typeof UPLOAD_CONFIG.fileTypes);
      if (!existsSync(path)) {
        mkdirSync(path, { recursive: true });
        this.logger.log(`Created upload directory for ${type}: ${path}`);
      }
    });
  }

  /**
   * Create multer storage configuration for a specific file type
   */
  createStorage(type: keyof typeof UPLOAD_CONFIG.fileTypes) {
    const destination = getUploadPath(type);

    return diskStorage({
      destination: (
        req: Request,
        file: MulterFile,
        cb: MulterDestinationCallback,
      ) => {
        try {
          cb(null, destination);
        } catch (error: unknown) {
          const message =
            error instanceof Error ? error.message : String(error);
          const stack = error instanceof Error ? error.stack : undefined;
          this.logger.error(`Storage destination error: ${message}`, stack);
          cb(
            error instanceof Error ? error : new Error(String(error)),
            destination,
          );
        }
      },
      filename: (
        req: Request,
        file: MulterFile,
        cb: MulterFilenameCallback,
      ) => {
        try {
          const uniqueName = this.generateFilename(file);
          cb(null, uniqueName);
        } catch (error: unknown) {
          const message =
            error instanceof Error ? error.message : String(error);
          const stack = error instanceof Error ? error.stack : undefined;
          this.logger.error(`Filename generation error: ${message}`, stack);
          cb(
            error instanceof Error ? error : new Error(String(error)),
            file.originalname,
          );
        }
      },
    });
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
   * Get upload limits for a specific file type
   */
  getUploadLimits(type: keyof typeof UPLOAD_CONFIG.fileTypes): UploadLimits {
    const config = UPLOAD_CONFIG.fileTypes[type];
    return {
      fileSize: config.maxSize,
      files: 1,
    };
  }

  /**
   * Generate a unique filename
   */
  private generateFilename(file: MulterFile): string {
    const extension = extname(file.originalname);
    const randomId = uuidv4();

    // Use uuid strategy for now (can be made configurable later)
    return `${randomId}${extension}`;
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
    const destination = UPLOAD_CONFIG.fileTypes[type].destination;
    return `/uploads/${destination}/${filename}`;
  }

  /**
   * Get full file path for a specific type and filename
   */
  getFullFilePath(
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    filename: string,
  ): string {
    const destination = getUploadPath(type);
    return join(destination, filename);
  }

  /**
   * Check if file exists
   */
  fileExists(
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    filename: string,
  ): boolean {
    const filePath = this.getFullFilePath(type, filename);
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
      if (!logoUri || typeof logoUri !== 'string') {
        this.logger.warn('Invalid logoUri provided for deletion');
        return false;
      }

      // Remove leading slash and extract relative path
      const relativePath = logoUri.startsWith('/') ? logoUri.slice(1) : logoUri;

      // Check if it's an upload path
      if (!relativePath.startsWith('uploads/')) {
        this.logger.warn(
          `File path does not start with 'uploads/': ${relativePath}`,
        );
        return false;
      }

      // Build absolute file path
      const filePath = join(process.cwd(), relativePath);

      // Check if file exists
      if (!existsSync(filePath)) {
        this.logger.warn(`File does not exist: ${filePath}`);
        return false;
      }

      // Delete the file
      unlinkSync(filePath);
      return true;
    } catch (error) {
      this.logger.error(
        `Failed to delete file: ${logoUri}`,
        error instanceof Error ? error.stack : String(error),
      );
      return false;
    }
  }
}
