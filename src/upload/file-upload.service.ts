import { Injectable, Logger } from '@nestjs/common';
import { extname, join } from 'path';
import { existsSync, mkdirSync, unlinkSync } from 'fs';
import { writeFile } from 'fs/promises';
import { memoryStorage } from 'multer';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import type { Request } from 'express';
import {
  MulterFile,
  UploadedFile,
  UploadLimits,
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

  /**
   * Upload and process an avatar file
   * @param file - The uploaded file from multer
   * @param userId - The user ID for filename generation
   * @param existingAvatarUrl - Optional existing avatar URL to delete
   * @returns Promise<string> - The URL of the uploaded avatar
   */
  private async processImage(
    type: 'logo' | 'avatar',
    file: MulterFile,
    userId?: number,
  ): Promise<string> {
    try {
      // Validate file type
      if (!file.mimetype.startsWith('image/')) {
        throw new FileUploadError(
          `Invalid file type for ${type}`,
          'INVALID_FILE_TYPE',
        );
      }

      // Validate file buffer
      if (
        !file.buffer ||
        !Buffer.isBuffer(file.buffer) ||
        file.buffer.length === 0
      ) {
        throw new FileUploadError(
          `Invalid or empty file buffer for ${type}`,
          'INVALID_FILE_BUFFER',
        );
      }

      // Generate unique filename using UUID
      const fileExtension =
        file.originalname.split('.').pop()?.toLowerCase() || '';
      const uniqueId = uuidv4();
      const filename =
        type === 'avatar' && userId
          ? `${type}_${userId}_${uniqueId}.${fileExtension}`
          : `${type}_${uniqueId}.${fileExtension}`;

      // Process image with Sharp: resize to 256x256, optimize size
      const processedBuffer = await sharp(file.buffer)
        .resize(256, 256, {
          fit: 'cover',
          position: 'center',
        })
        .jpeg({ quality: 85, mozjpeg: true })
        .png({ compressionLevel: 9 })
        .toBuffer();

      // Save processed file
      const destinationPath = getUploadPath(type);
      const fullPath = join(destinationPath, filename);

      // Ensure destination directory exists
      if (!existsSync(destinationPath)) {
        mkdirSync(destinationPath, { recursive: true });
      }

      await writeFile(fullPath, processedBuffer);

      // Get file URL using standard pattern
      const imageUrl = this.getFileUrl(type, filename);

      this.logger.log(
        `${type.charAt(0).toUpperCase() + type.slice(1)} processed${
          userId ? ` for user ${userId}` : ''
        }: ${filename}`,
      );
      return imageUrl;
    } catch (error) {
      // Handle Sharp-specific errors
      if (error instanceof Error && error.message.includes('Invalid input')) {
        this.logger.error(
          `Invalid image format or corrupted file for ${type}: ${error.message}`,
          error.stack,
        );
        throw new FileUploadError(
          `Invalid image format for ${type}. Please upload a valid image file.`,
          'INVALID_IMAGE_FORMAT',
        );
      }

      this.logger.error(
        `Failed to process ${type} image: ${
          error instanceof Error ? error.message : String(error)
        }`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new FileUploadError(
        `Failed to process ${type} file`,
        'PROCESS_FAILED',
      );
    }
  }

  async processLogoImage(file: MulterFile): Promise<string> {
    return this.processImage('logo', file);
  }

  async processAvatarImage(userId: number, file: MulterFile): Promise<string> {
    return this.processImage('avatar', file, userId);
  }
}
